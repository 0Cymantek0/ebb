package cli

import "runtime"

// goVersion reports the toolchain the binary was built with.
func goVersion() string { return runtime.Version() }
