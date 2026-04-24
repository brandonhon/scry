// Command gen-man generates the scry(1) man page from the cobra tree.
//
// Invoked from `make man`. Not shipped in the scry binary itself, so
// cobra/doc stays out of the release artifact.
//
// Usage: gen-man <output-dir>
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/brandonhon/scry/internal/cli"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-man <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	root := cli.NewRootCmd(io.Discard, io.Discard)
	header := &doc.GenManHeader{
		Title:   "SCRY",
		Section: "1",
		Source:  "scry " + cli.Version,
		Manual:  "scry Manual",
	}
	if err := doc.GenManTree(root, header, outDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote man page(s) to %s\n", outDir)
}
