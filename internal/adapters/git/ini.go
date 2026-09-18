package gitadapter

import "strings"

// Pure-Go .gitmodules parsing (D004 rule 4). The submodule map is an INI
// file; `git config --file` never executes and needs no repository, but it
// is still an extra subprocess surface over attacker-controlled bytes, so
// the ~30-line reader below is preferred. Only `[submodule "name"]`
// section names are needed; entries are never initialized.

// parseGitmodulesINI returns the submodule names declared in a
// .gitmodules file. It understands the INI subset git writes: section
// headers (`[section]`, `[section "subsection"]`), `key = value` lines,
// `;` and `#` comments, and backslash escapes inside quoted subsections.
// Malformed lines are skipped, never trusted.
func parseGitmodulesINI(data []byte) []string {
	var names []string
	inSubmodule := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		switch {
		case line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "["):
			end := strings.IndexByte(line, ']')
			if end < 0 {
				inSubmodule = false
				continue
			}
			header := line[1:end]
			sec, sub, _ := strings.Cut(header, " ")
			if strings.EqualFold(strings.TrimRight(sec, " \t"), "submodule") {
				name := unquoteINISubsection(strings.TrimSpace(sub))
				if name != "" {
					names = append(names, name)
					inSubmodule = true
					continue
				}
			}
			inSubmodule = false
		default:
			// key = value lines: irrelevant to the name list; tracked only
			// so the parser's shape stays honest for future use.
			_ = inSubmodule
		}
	}
	return names
}

// unquoteINISubsection removes the surrounding double quotes of a
// subsection name and resolves \" and \\ escapes. A missing closing quote
// yields "" (git would reject the file; we skip the entry).
func unquoteINISubsection(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return ""
	}
	body := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) && (body[i+1] == '"' || body[i+1] == '\\') {
			b.WriteByte(body[i+1])
			i++
			continue
		}
		b.WriteByte(body[i])
	}
	return b.String()
}
