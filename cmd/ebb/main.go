// Command ebb reclaims developer workspace disk space with verified
// recovery. This is the thin process entry point; all dispatch, exit
// codes and presentation live in ebb/internal/cli (Foundation §17).
package main

import (
	"os"

	"ebb/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.Streams{Out: os.Stdout, Err: os.Stderr}, cli.RealDeps()))
}
