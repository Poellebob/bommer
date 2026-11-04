package main

import (
	"bytes"
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

const overviewHelp = `usage: bommer <command> [options]

Collect hardware, software, and application cryptography inventories in CycloneDX format.

Commands:
  doctor   Check configuration and collector prerequisites without scanning
  scan     Collect the inventories enabled in your configuration
  version  Print the Bommer version
  help     Show this overview or help for a command

Options:
  -h, --help  Show this help message
  --version   Print the Bommer version

Examples:
  bommer doctor --config config.yaml
  bommer scan --config config.yaml
  bommer scan --config config.yaml --only sbom
  bommer scan --config config.yaml --application payments

Run 'bommer help <command>' for command-specific options.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func cli(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(out, overviewHelp)
		return 0
	}

	command := args[0]
	if command == "help" || command == "--help" || command == "-h" {
		if len(args) == 1 {
			fmt.Fprint(out, overviewHelp)
			return 0
		}
		if command == "help" && len(args) == 2 {
			return cli(ctx, []string{args[1], "--help"}, out, errOut)
		}
		fmt.Fprintln(errOut, "usage: bommer help [command]")
		return 2
	}
	if command == "version" || command == "--version" {
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fmt.Fprintln(out, "usage: bommer version\n\nPrint the Bommer version.")
			return 0
		}
		if len(args) != 1 {
			fmt.Fprintln(errOut, "usage: bommer version")
			return 2
		}
		fmt.Fprintln(out, version)
		return 0
	}
	if command != "doctor" && command != "scan" {
		fmt.Fprintln(errOut, "unknown command:", command)
		fmt.Fprintln(errOut, "Run 'bommer --help' for available commands.")
		return 2
	}

	// Buffer parser messages so requested help goes to stdout and errors to stderr.
	var flagMessages bytes.Buffer
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(&flagMessages)
	flags.Usage = func() {
		fmt.Fprintf(&flagMessages, "usage: bommer %s [options]\n\n", command)
		if command == "doctor" {
			fmt.Fprintln(&flagMessages, "Check configuration and collector prerequisites without scanning.")
		} else {
			fmt.Fprintln(&flagMessages, "Collect the inventories enabled in your configuration.")
		}
		fmt.Fprintln(&flagMessages, "\nOptions:")
		flags.PrintDefaults()
		fmt.Fprintln(&flagMessages, "  -h, --help\n    \tShow this help message")
	}
	configPath := flags.String("config", "/etc/bommer/config.yaml", "configuration file")
	only := flags.String("only", "", "inventory kind: hbom, sbom, or cbom")
	application := flags.String("application", "", "application name (excludes host)")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, flagMessages.String())
			return 0
		}
		fmt.Fprint(errOut, flagMessages.String())
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
			label := job.Name
			if job.Inventory != "" {
				label += "/" + job.Inventory
			}
			err := job.Check()
			if err == nil {
				checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, err = job.Resolve(checkContext)
				cancel()
			}
			if err != nil {
				fmt.Fprintf(out, "FAIL %s/%s: %v\n", label, job.Kind, err)
				exitCode = 1
			} else {
				fmt.Fprintf(out, "READY %s/%s (%s); discovery coverage not verified\n", label, job.Kind, job.Collector.Backend)
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
		fmt.Fprintln(errOut, "one or more collectors failed or reported partial coverage; inspect manifest.json")
		return 1
	}
	return 0
}
