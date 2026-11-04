package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"codeberg.org/Poellebob/bommer/internal/collect"
	"codeberg.org/Poellebob/bommer/internal/config"
	"codeberg.org/Poellebob/bommer/internal/run"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func cli(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: bommer <version|doctor|scan> [--config path] [--only hbom|sbom|cbom] [--application name]")
		return 2
	}

	command := args[0]
	if command == "version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if command != "doctor" && command != "scan" {
		fmt.Fprintln(errOut, "unknown command:", command)
		return 2
	}

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "/etc/bommer/config.yaml", "configuration file")
	only := flags.String("only", "", "inventory kind")
	application := flags.String("application", "", "application name (excludes host)")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errOut, "unexpected positional arguments")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	jobs, err := collect.Jobs(cfg, *only, *application)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	if command == "doctor" {
		exitCode := 0
		for _, job := range jobs {
			err := job.Check()
			if err == nil {
				checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, err = job.Resolve(checkContext)
				cancel()
			}
			if err != nil {
				fmt.Fprintf(out, "FAIL %s/%s: %v\n", job.Name, job.Kind, err)
				exitCode = 1
			} else {
				fmt.Fprintf(out, "READY %s/%s (%s); discovery coverage not verified\n", job.Name, job.Kind, job.Collector.Backend)
			}
		}
		return exitCode
	}

	// Configuration validation has already checked the duration.
	timeout, _ := time.ParseDuration(cfg.Timeout)
	runDirectory, failed, err := run.Execute(ctx, jobs, cfg.Output.Directory, timeout, version)
	if runDirectory != "" {
		fmt.Fprintln(out, runDirectory)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if failed {
		fmt.Fprintln(errOut, "one or more collectors failed; inspect manifest.json")
		return 1
	}
	return 0
}
