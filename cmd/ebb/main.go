// Command ebb reclaims developer workspace disk space with verified
// recovery. This is the thin process entry point; all dispatch, exit
// codes and presentation live in ebb/internal/cli (Foundation §17).
package main

import (
	"os"

	"ebb/internal/cli"
)

// Version is the build version this binary reports. Release builds
// override it at link time (scripts/release.sh passes -X for both the
// "main.Version" spelling — what the linker resolves for package main
// on go1.27 — and the import-path spelling); the default marks a
// non-release build.
var Version = "0.1.0-dev"

func main() {
	cli.Version = Version
	os.Exit(cli.Main(os.Args[1:], cli.Streams{Out: os.Stdout, Err: os.Stderr}, cli.RealDeps()))
}
