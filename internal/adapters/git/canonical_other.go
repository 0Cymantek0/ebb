//go:build !windows

package gitadapter

// canonicalForm is the identity on non-Windows platforms: 8.3 short
// names are a Windows NTFS concept. Keeping the seam per-platform (not
// runtime.GOOS inside one file) is what keeps GOOS=linux buildable.
func canonicalForm(path string) string { return path }
