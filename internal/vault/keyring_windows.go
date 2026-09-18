//go:build windows

package vault

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Credential Manager binding via LazyDLL advapi32 (the
// Tailscale precedent: thin syscall shims over CredReadW/CredWriteW/
// CredDeleteW, resolved once under sync.Once so a stripped-down session
// fails with a clean typed error instead of a panic deep in a call).
//
// Entries are generic credentials (CRED_TYPE_GENERIC) with
// CRED_PERSIST_LOCAL_MACHINE (survive reboot, roam with neither the
// profile nor a domain account — a machine-local convenience unlock;
// disaster recovery is the separately recorded recovery secret,
// Foundation §13.1). The blob is the exact UTF-8 password bytes; only
// this package reads it back, so no UTF-16 conversion is imposed.

const (
	credTypeGeneric         = 1 // CRED_TYPE_GENERIC
	credPersistLocalMachine = 2 // CRED_PERSIST_LOCAL_MACHINE
	// credMaxBlob is CRED_MAX_CREDENTIAL_BLOB_SIZE (5*512).
	credMaxBlob = 2560
)

// credential mirrors the x64/arm64 CREDENTIALW layout exactly: two
// uint32 flag words, pointers, FILETIME, then the size/pad/pointer
// triple. Go's alignment rules produce the same offsets as the C struct
// on every supported Windows architecture.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW   = advapi32.NewProc("CredReadW")
	procCredWriteW  = advapi32.NewProc("CredWriteW")
	procCredDeleteW = advapi32.NewProc("CredDeleteW")
	procCredFree    = advapi32.NewProc("CredFree")

	procsOnce sync.Once
	procsErr  error
)

// loadProcs resolves every proc address once; failures are sticky and
// surfaced as typed errors from all keyring calls.
func loadProcs() error {
	procsOnce.Do(func() {
		for _, p := range []*windows.LazyProc{procCredReadW, procCredWriteW, procCredDeleteW, procCredFree} {
			if err := p.Find(); err != nil {
				procsErr = fmt.Errorf("vault: advapi32.%s unavailable: %w", p.Name, err)
				return
			}
		}
	})
	return procsErr
}

// credErr maps a failed advapi32 call to an error, translating
// ERROR_NOT_FOUND into a wrapped ErrNotFound (missing entry).
func credErr(op, target string, err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == windows.ERROR_NOT_FOUND {
			return fmt.Errorf("%s %q: %w", op, target, ErrNotFound)
		}
		return fmt.Errorf("vault: %s credential %q: %w", op, target, errno)
	}
	return fmt.Errorf("vault: %s credential %q: %w", op, target, err)
}

func init() {
	keyringGet = windowsKeyringGet
	keyringSet = windowsKeyringSet
	keyringDelete = windowsKeyringDelete
	keyringExists = windowsKeyringExists
}

// windowsKeyringGet reads the generic credential blob for target and
// returns it as a string (exact bytes, no trimming).
func windowsKeyringGet(target string) (string, error) {
	if err := loadProcs(); err != nil {
		return "", err
	}
	targ, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", fmt.Errorf("vault: credential target: %w", err)
	}
	var cred *credential
	r1, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targ)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&cred)),
	)
	if r1 == 0 {
		return "", credErr("read", target, callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))
	if cred.Type != credTypeGeneric {
		return "", fmt.Errorf("vault: credential %q: unexpected type %d", target, cred.Type)
	}
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		// CredWrite never stores an empty blob from this package; treat
		// one as a missing entry rather than an unusable password.
		return "", fmt.Errorf("read %q: %w", target, ErrNotFound)
	}
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	return string(blob), nil
}

// windowsKeyringSet writes (or overwrites) the generic credential for
// target with the exact UTF-8 bytes of secret.
func windowsKeyringSet(target, secret string) error {
	if err := loadProcs(); err != nil {
		return err
	}
	if secret == "" {
		return errors.New("vault: refusing to store an empty credential")
	}
	if len(secret) > credMaxBlob {
		return fmt.Errorf("vault: secret too large for credential store (%d > %d bytes)", len(secret), credMaxBlob)
	}
	targ, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("vault: credential target: %w", err)
	}
	user, err := windows.UTF16PtrFromString("ebb")
	if err != nil {
		return fmt.Errorf("vault: credential user: %w", err)
	}
	blob := []byte(secret)
	c := &credential{
		Type:               credTypeGeneric,
		TargetName:         targ,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	r1, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(c)), 0)
	if r1 == 0 {
		return credErr("write", target, callErr)
	}
	return nil
}

// windowsKeyringDelete removes the generic credential for target.
func windowsKeyringDelete(target string) error {
	if err := loadProcs(); err != nil {
		return err
	}
	targ, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("vault: credential target: %w", err)
	}
	r1, _, callErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targ)),
		uintptr(credTypeGeneric),
		0,
	)
	if r1 == 0 {
		return credErr("delete", target, callErr)
	}
	return nil
}

// windowsKeyringExists reports whether a generic credential exists for
// target. Store failures other than not-found are returned as errors.
func windowsKeyringExists(target string) (bool, error) {
	_, err := windowsKeyringGet(target)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}
