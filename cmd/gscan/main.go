// Command gscan is a fast IP/port scanner.
//
// See ip-scanner-plan.md for the full design.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/bhoneycutt/gscan/internal/cli"
	"github.com/bhoneycutt/gscan/internal/output"
)

func main() {
	output.EnableVT()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := cli.NewRootCmd(os.Stdout, os.Stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
