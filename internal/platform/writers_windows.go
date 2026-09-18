//go:build windows

package platform

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// rstrtmgr.dll — the Windows Restart Manager, used ONLY to list
// processes holding handles to files (diagnostics per Foundation
// §4.4/§12.3: explain errno-32 removal blockers; never restart, never
// shut down, never treat an open handle as proof of mutation).
// Binding modeled on Tailscale util/winutil/restartmgr_windows.go
// (BSD-3-Clause); the restart/terminate half of that API is
// deliberately not bound.
var (
	modRstrtmgr = windows.NewLazySystemDLL("rstrtmgr.dll")

	pRmStartSession      = modRstrtmgr.NewProc("RmStartSession")
	pRmRegisterResources = modRstrtmgr.NewProc("RmRegisterResources")
	pRmGetList           = modRstrtmgr.NewProc("RmGetList")
	pRmEndSession        = modRstrtmgr.NewProc("RmEndSession")

	rmProcsOnce sync.Once
	rmProcsErr  error
)

// rmUniqueProcess mirrors RM_UNIQUE_PROCESS (PID + creation time to
// survive PID reuse).
type rmUniqueProcess struct {
	processID        uint32
	processStartTime windows.Filetime
}

// rmAppType mirrors RM_APP_TYPE.
type rmAppType int32

const (
	rmUnknownApp  rmAppType = 0
	rmMainWindow  rmAppType = 1
	rmOtherWindow rmAppType = 2
	rmService     rmAppType = 3
	rmExplorer    rmAppType = 4
	rmConsole     rmAppType = 5
	rmCritical    rmAppType = 1000
)

// rmProcessInfo mirrors RM_PROCESS_INFO.
type rmProcessInfo struct {
	process          rmUniqueProcess
	appName          [256]uint16
	serviceShortName [64]uint16
	applicationType  rmAppType
	appStatus        uint32
	tsSessionID      uint32
	restartable      int32
}

// cchRMSessionKey is CCH_RM_SESSION_KEY (32, excluding NUL).
const cchRMSessionKey = 32

// resolveRMProcs resolves the Restart Manager bindings once.
func resolveRMProcs() error {
	rmProcsOnce.Do(func() {
		for _, p := range []*windows.LazyProc{
			pRmStartSession, pRmRegisterResources, pRmGetList, pRmEndSession,
		} {
			if err := p.Find(); err != nil {
				rmProcsErr = fmt.Errorf("rstrtmgr.dll: %w", err)
				return
			}
		}
	})
	return rmProcsErr
}

// rmInspector lists writers via the Restart Manager.
type rmInspector struct{}

// newNativeWriterInspector returns the Windows writer inspector (see
// platform.go NewWriterInspector).
func newNativeWriterInspector() (WriterInspector, error) {
	if err := resolveRMProcs(); err != nil {
		return nil, err
	}
	return rmInspector{}, nil
}

// InspectWriters registers paths with a fresh Restart Manager session
// and returns the processes the kernel reports as using them. Paths are
// made absolute (RM requires fully-qualified names). The session is
// always ended; no process is ever restarted or terminated.
func (rmInspector) InspectWriters(paths []string) ([]Writer, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if err := resolveRMProcs(); err != nil {
		return nil, err
	}

	ptrs := make([]*uint16, 0, len(paths))
	for _, p := range paths {
		a, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("writer inspection %q: %w", p, err)
		}
		a16, err := windows.UTF16PtrFromString(a)
		if err != nil {
			return nil, fmt.Errorf("writer inspection %q: %w", p, err)
		}
		ptrs = append(ptrs, a16)
	}

	var session uint32
	var key [cchRMSessionKey + 1]uint16
	if err := rmCall(pRmStartSession,
		uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0]))); err != nil {
		return nil, fmt.Errorf("RmStartSession: %w", err)
	}
	defer func() { _ = rmCall(pRmEndSession, uintptr(session)) }()

	if err := rmCall(pRmRegisterResources,
		uintptr(session), uintptr(len(ptrs)),
		uintptr(unsafe.Pointer(&ptrs[0])), 0, 0, 0, 0); err != nil {
		return nil, fmt.Errorf("RmRegisterResources(%d paths): %w", len(paths), err)
	}

	infos, err := rmGetList(session)
	if err != nil {
		return nil, fmt.Errorf("RmGetList: %w", err)
	}

	writers := make([]Writer, 0, len(infos))
	seen := make(map[uint32]bool, len(infos))
	for i := range infos {
		pid := infos[i].process.processID
		if seen[pid] {
			continue
		}
		seen[pid] = true
		appName := windows.UTF16ToString(infos[i].appName[:])
		writers = append(writers, Writer{
			Name:   appName,
			PID:    pid,
			Kind:   classifyWriter(appName, infos[i].applicationType),
			Source: "restart-manager",
		})
	}
	return writers, nil
}

// rmGetList walks the ERROR_MORE_DATA growth pattern: RM reports the
// needed count and the caller retries with a bigger buffer (at most 5
// attempts, following the Tailscale reference).
func rmGetList(session uint32) ([]rmProcessInfo, error) {
	const maxAttempts = 5
	var needed, avail, rebootReasons uint32
	buf := make([]rmProcessInfo, 1)
	err := error(windows.ERROR_MORE_DATA)
	for attempts := 0; err == windows.ERROR_MORE_DATA && attempts < maxAttempts; attempts++ {
		avail = uint32(len(buf))
		err = rmCall(pRmGetList,
			uintptr(session), uintptr(unsafe.Pointer(&needed)),
			uintptr(unsafe.Pointer(&avail)),
			uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
			uintptr(unsafe.Pointer(&rebootReasons)))
		if err == windows.ERROR_MORE_DATA && needed > uint32(len(buf)) {
			buf = make([]rmProcessInfo, needed)
		}
	}
	if err != nil {
		return nil, err
	}
	return buf[:avail], nil
}

// rmCall invokes an RM entry point; these functions return a Win32
// error code directly (0 == success), unlike usual BOOL APIs.
func rmCall(p *windows.LazyProc, args ...uintptr) error {
	r1, _, e1 := p.Call(args...)
	if r1 != 0 {
		return e1
	}
	return nil
}

// classifyWriter maps (image name, RM app type) to a coarse Kind.
// Name-based editor detection is a display heuristic only; the
// Source field always records the real provenance.
func classifyWriter(appName string, t rmAppType) string {
	base := strings.ToLower(filepath.Base(appName))
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	switch stem {
	case "code", "code-insiders", "cursor", "sublime_text", "notepad++",
		"notepad", "nvim", "vim", "gvim", "emacs", "idea", "idea64",
		"webstorm64", "pycharm64", "goland64", "studio64":
		return "editor"
	}
	switch t {
	case rmService:
		return "service"
	case rmExplorer:
		return "shell"
	case rmConsole:
		return "console"
	case rmCritical:
		return "critical"
	default:
		return "process"
	}
}
