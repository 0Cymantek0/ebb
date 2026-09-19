package capsule

// public.go — the bounded public-metadata reader behind `ebb inspect
// <capsule-file>` (Foundation §15.3: "reads bounded public metadata"):
// ReadPublicInfo verifies the container STRUCTURALLY (the same
// verifyPackage gate every import runs in its preflight) and returns
// only what §15.1 allows to be public — the bootstrap descriptor's
// fields, the declared repository totals from ebb-export.json, and the
// file's size. It needs no passphrase, extracts nothing and mutates no
// vault.

import "os"

// PublicInfo is the public face of one capsule file.
type PublicInfo struct {
	// Producer labels the exporting tool ("ebb <version>").
	Producer string
	// ContainerVersion is the §15.1 container layout version.
	ContainerVersion int
	// BackendFamily names the inner repository's backend ("restic").
	BackendFamily string
	// RepoRoot is the declared repository-relative root ("repo").
	RepoRoot string
	// MinReaderFeatures are the features a reader must support
	// (zip64, zip-stored-entries, restic).
	MinReaderFeatures []string
	// RepoEntries / RepoBytes are the DECLARED repository totals from
	// the container's identification document — cross-checked against
	// the actual entries by the structural verification before this
	// struct is returned.
	RepoEntries int64
	RepoBytes   int64
	// CapsuleBytes is the capsule file's size on disk.
	CapsuleBytes int64
}

// ReadPublicInfo structurally verifies the capsule at path and returns
// its public metadata. A missing file, a non-regular file or any
// structural failure refuses as *ErrNotACapsule (at the CLI the file
// argument is not a valid capsule — an argument mistake, exit 2). The
// passphrase-gated half of the capsule is never touched.
func ReadPublicInfo(path string) (PublicInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return PublicInfo{}, &ErrNotACapsule{Path: path, Details: []string{err.Error()}}
	}
	if !fi.Mode().IsRegular() {
		return PublicInfo{}, &ErrNotACapsule{Path: path, Details: []string{"not a regular file"}}
	}
	check, err := verifyPackage(path)
	if err != nil {
		return PublicInfo{}, &ErrNotACapsule{Path: path, Details: []string{err.Error()}}
	}
	return PublicInfo{
		Producer:          check.Bootstrap.Producer,
		ContainerVersion:  check.Bootstrap.ContainerVersion,
		BackendFamily:     check.Bootstrap.BackendFamily,
		RepoRoot:          check.Bootstrap.RepoRoot,
		MinReaderFeatures: check.Bootstrap.MinReaderFeatures,
		RepoEntries:       check.ExportDoc.RepoEntries,
		RepoBytes:         check.ExportDoc.RepoBytes,
		CapsuleBytes:      fi.Size(),
	}, nil
}
