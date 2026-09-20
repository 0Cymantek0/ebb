// cmd_config.go implements `ebb config <subcommand>` (product evolution
// plan §2/§11.1; D032/D037 groundwork): persistent global configuration
// holding PATHS ONLY (no secret may ever enter this document —
// Foundation §13 keeps secrets in the OS credential store and ephemeral
// passfiles). v1 carries exactly one list-valued key, "projects_dir" —
// the parent scan roots Wave 2's `ebb analyse` will consume.
//
//	ebb config list
//	ebb config get <key>
//	ebb config set <key> <value>     (replaces the key's whole list)
//	ebb config add <key> <value>
//	ebb config remove <key> <value>
//
// The document is one config.json inside the state directory
// (vault.DefaultConfigDir — EBB_STATE_DIR isolation covers it), written
// atomically by internal/config. Missing file = empty configuration.
//
// Exit contract: 0 ok; 2 usage (shape mistakes, unknown key, bad or
// absent value); 3 state I/O failure (the same blocked class the
// session machinery uses for state-dir/catalog failures — errors.go has
// no dedicated state-file class, and its unknown-infrastructure default
// is blocked).

package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"ebb/internal/config"
)

// Stable CLI blocker codes for the config surface (§5.5). The
// internal/config typed errors carry the facts; these codes carry the
// stable wording.
const (
	CodeConfigUnknownKey = "EBB_E_CONFIG_UNKNOWN_KEY"
	CodeConfigBadValue   = "EBB_E_CONFIG_BAD_VALUE"
	CodeConfigNotPresent = "EBB_E_CONFIG_NOT_PRESENT"
)

// configDetails is the --json payload of every config subcommand: the
// resulting configuration state (§17.2 details).
type configDetails struct {
	SchemaVersion int      `json:"schema_version"`
	ProjectsDir   []string `json:"projects_dir"`
}

func configDetailsOf(c *config.Config) configDetails {
	return configDetails{SchemaVersion: config.SchemaVersion, ProjectsDir: c.ProjectsDirs()}
}

// configActionFor maps a typed internal/config error onto a §5.5-worded
// usage-class cliError; anything else is state I/O (blocked class).
func configActionFor(err error) error {
	switch {
	case errors.Is(err, config.ErrUnknownKey):
		return usageError(fmt.Errorf("%s: %v. Safe action: v1 supports only the key %q (see `ebb config list`)",
			CodeConfigUnknownKey, err, config.KeyProjectsDir))
	case errors.Is(err, config.ErrRelativePath):
		return usageError(fmt.Errorf("%s: %v. Safe action: pass an absolute path (the directory need not exist — offline/external drives are valid)",
			CodeConfigBadValue, err))
	case errors.Is(err, config.ErrTooManyValues):
		return usageError(fmt.Errorf("%s: %v. Safe action: remove an existing entry first (`ebb config remove %s <path>`)",
			CodeConfigBadValue, err, config.KeyProjectsDir))
	case errors.Is(err, config.ErrNotPresent):
		return usageError(fmt.Errorf("%s: %v. Safe action: check the stored spelling with `ebb config get %s`",
			CodeConfigNotPresent, err, config.KeyProjectsDir))
	default:
		return blockedError(fmt.Errorf("config: state I/O: %v", err))
	}
}

func cmdConfig(args []string, streams Streams, deps Deps) int {
	// `ebb config --json list` and `ebb config list --json` are both
	// accepted: leading --json tokens are lifted before the subcommand
	// dispatch (the sub-flagset still accepts trailing ones).
	jsonBefore := false
	rest := args
	for len(rest) > 0 && rest[0] == "--json" {
		jsonBefore = true
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(streams.Err, "ebb config: takes a subcommand: list | get <key> | set <key> <value> | add <key> <value> | remove <key> <value>")
		return ExitUsage
	}
	sub := rest[0]
	rest = rest[1:]
	fs := flag.NewFlagSet("config "+sub, flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(reorderFlags(rest)); err != nil {
		return ExitUsage
	}
	*jsonOut = *jsonOut || jsonBefore
	wantArgs := map[string]int{"list": 0, "get": 1, "set": 2, "add": 2, "remove": 2}
	n, known := wantArgs[sub]
	if !known {
		fmt.Fprintf(streams.Err, "ebb config: unknown subcommand %q (want list | get | set | add | remove)\n", sub)
		return ExitUsage
	}
	if fs.NArg() != n {
		fmt.Fprintf(streams.Err, "ebb config %s: takes %d argument(s)\n", sub, n)
		return ExitUsage
	}

	if deps.StateDir == nil {
		return emitFailure(newEnvelope("config", "error"), *jsonOut, streams, ExitUsage,
			fmt.Sprintf("ebb config: state dir %v", ErrNotIntegrated))
	}
	dir, err := deps.StateDir()
	if err != nil {
		return emitFailure(newEnvelope("config", "error"), *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("ebb config: state directory: %v", err))
	}
	env := newEnvelope("config", "error")
	cfg, err := config.Load(dir)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf("ebb config: load: %v", err))
	}

	switch sub {
	case "list":
		env.Outcome = "ok"
		env.Details = configDetailsOf(cfg)
		emit(env, *jsonOut, streams, renderConfigHuman("configuration", configDetailsOf(cfg)))
		return ExitOK
	case "get":
		key := fs.Arg(0)
		values, ok := cfg.Get(key)
		if !ok {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb config get: %s: %q is not a v1 configuration key. Safe action: see `ebb config list`",
					CodeConfigUnknownKey, key))
		}
		env.Outcome = "ok"
		env.Details = configDetailsOf(cfg)
		emit(env, *jsonOut, streams, renderConfigValues(key, values))
		return ExitOK
	case "set":
		key, value := fs.Arg(0), fs.Arg(1)
		if _, ok := cfg.Get(key); !ok {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb config set: %s: %q is not a v1 configuration key. Safe action: see `ebb config list`",
					CodeConfigUnknownKey, key))
		}
		if err := cfg.Set(key, []string{value}); err != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf("ebb config set: %v", configActionFor(err)))
		}
	case "add":
		key, value := fs.Arg(0), fs.Arg(1)
		if _, ok := cfg.Get(key); !ok {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb config add: %s: %q is not a v1 configuration key. Safe action: see `ebb config list`",
					CodeConfigUnknownKey, key))
		}
		if err := cfg.AddProjectsDir(value); err != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf("ebb config add: %v", configActionFor(err)))
		}
	case "remove":
		key, value := fs.Arg(0), fs.Arg(1)
		if _, ok := cfg.Get(key); !ok {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb config remove: %s: %q is not a v1 configuration key. Safe action: see `ebb config list`",
					CodeConfigUnknownKey, key))
		}
		if err := cfg.RemoveProjectsDir(value); err != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf("ebb config remove: %v", configActionFor(err)))
		}
	}

	if err := cfg.Save(dir); err != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf("ebb config %s: save: %v", sub, err))
	}
	env.Outcome = "ok"
	env.Conditions = []string{sub + "-applied"}
	emit(env, *jsonOut, streams, renderConfigHuman("ebb config "+sub, configDetailsOf(cfg)))
	return ExitOK
}

// renderConfigHuman renders the resulting state for list/mutations.
func renderConfigHuman(title string, d configDetails) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (schema %d)\n", title, d.SchemaVersion)
	fmt.Fprintf(&b, "  projects_dir:\n")
	if len(d.ProjectsDir) == 0 {
		fmt.Fprintf(&b, "    (none configured)\n")
	}
	for _, p := range d.ProjectsDir {
		fmt.Fprintf(&b, "    %s\n", p)
	}
	return b.String()
}

// renderConfigValues renders one key's values for `config get`.
func renderConfigValues(key string, values []string) string {
	var b strings.Builder
	if len(values) == 0 {
		fmt.Fprintf(&b, "%s: (none configured)\n", key)
	}
	for _, v := range values {
		fmt.Fprintf(&b, "%s\n", v)
	}
	return b.String()
}
