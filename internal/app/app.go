// Package app implements the Envelode command line and JSON report.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/subsll/envelode/internal/email"
	"github.com/subsll/envelode/internal/recon"
)

// Version is overridden at build time.
var Version = "0.1.0"

const defaultMaxFileSize = 64 << 20

type Report struct {
	Tool           string           `json:"tool"`
	Version        string           `json:"version"`
	GeneratedAt    string           `json:"generated_at"`
	Resolver       string           `json:"resolver,omitempty"`
	ContentOmitted bool             `json:"content_omitted"`
	Messages       []*email.Message `json:"messages"`
	DNS            *recon.Report    `json:"dns,omitempty"`
	Errors         []string         `json:"errors,omitempty"`
}

type input struct {
	path string
}

// Run executes Envelode and returns a process exit code.
func Run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("envelode", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var (
		outPath   string
		noDNS     bool
		dnsServer string
		timeout   time.Duration
		compact   bool
		maxSize   int64
		version   bool
	)
	fs.StringVar(&outPath, "o", "", "write JSON to this file (default stdout)")
	fs.StringVar(&outPath, "out", "", "write JSON to this file (default stdout)")
	fs.BoolVar(&noDNS, "no-dns", false, "skip passive DNS enrichment")
	fs.StringVar(&dnsServer, "dns-server", "", "DNS server host[:port] (default: system resolver)")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "per-DNS-query timeout")
	fs.BoolVar(&compact, "compact", false, "compact JSON")
	fs.Int64Var(&maxSize, "max-size", defaultMaxFileSize, "maximum input file size in bytes")
	fs.BoolVar(&version, "version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: envelode [flags] <file|directory|->...")
		fmt.Fprintln(errOut, "")
		fmt.Fprintln(errOut, "Parse EML/raw RFC 5322 messages into metadata-only JSON.")
		fmt.Fprintln(errOut, "Message bodies are never included; attachments are metadata only.")
		fmt.Fprintln(errOut, "")
		fmt.Fprintln(errOut, "options:")
		fs.PrintDefaults()
	}

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.Usage()
			return 0
		}
		fmt.Fprintf(errOut, "envelode: %v\n", err)
		fs.Usage()
		return 2
	}
	if version {
		fmt.Fprintf(out, "envelode %s (%s %s/%s)\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}
	if maxSize <= 0 {
		fmt.Fprintln(errOut, "envelode: --max-size must be positive")
		return 2
	}
	if len(pos) == 0 {
		fs.Usage()
		return 2
	}

	inputs, err := expandInputs(pos)
	if err != nil {
		fmt.Fprintf(errOut, "envelode: %v\n", err)
		return 2
	}

	report := &Report{
		Tool:           "envelode",
		Version:        Version,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		ContentOmitted: true,
		Messages:       []*email.Message{},
	}
	var domains, ips []string
	selectors := make(map[string][]string)

	for _, in := range inputs {
		data, err := readInput(in.path, maxSize)
		if err != nil {
			report.Errors = append(report.Errors, in.label()+": "+err.Error())
			continue
		}
		msg, err := email.Parse(data, in.label())
		if err != nil {
			report.Errors = append(report.Errors, in.label()+": "+err.Error())
			continue
		}
		report.Messages = append(report.Messages, msg)
		domains = append(domains, msg.Domains...)
		ips = append(ips, msg.IPs...)
		for _, dkim := range msg.Authentication.DKIM {
			if dkim.Domain != "" && dkim.Selector != "" {
				selectors[dkim.Domain] = appendUnique(selectors[dkim.Domain], dkim.Selector)
			}
		}
	}

	if !noDNS && (len(domains) > 0 || len(ips) > 0) {
		resolver, resolvedBy, err := recon.NewResolver(dnsServer, timeout)
		if err != nil {
			report.Errors = append(report.Errors, "DNS resolver: "+err.Error())
		} else {
			report.Resolver = resolvedBy
			report.DNS = recon.Run(context.Background(), recon.Options{
				Resolver: resolver, Timeout: timeout, Domains: domains,
				Selectors: selectors, IPs: ips,
			})
		}
	}

	if err := writeReport(outPath, out, report, compact); err != nil {
		fmt.Fprintf(errOut, "envelode: %v\n", err)
		return 1
	}
	if len(report.Errors) > 0 {
		return 1
	}
	return 0
}

func writeReport(path string, out io.Writer, report *Report, compact bool) error {
	var data []byte
	var err error
	if compact {
		data, err = json.Marshal(report)
	} else {
		data, err = json.MarshalIndent(report, "", "  ")
	}
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "" {
		_, err = out.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (in input) label() string {
	if in.path == "-" {
		return "stdin"
	}
	return in.path
}

func readInput(path string, max int64) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > max {
			return nil, fmt.Errorf("stdin exceeds %d bytes", max)
		}
		return data, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return os.ReadFile(path)
}

func expandInputs(args []string) ([]input, error) {
	var inputs []input
	for _, arg := range args {
		if arg == "-" {
			inputs = append(inputs, input{path: "-"})
			continue
		}
		st, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			var found []input
			err := filepath.WalkDir(arg, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				if !d.Type().IsRegular() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				switch ext {
				case ".eml", ".emlx", ".mail", ".txt":
					found = append(found, input{path: path})
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
			inputs = append(inputs, found...)
			continue
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file or directory", arg)
		}
		inputs = append(inputs, input{path: arg})
	}
	if len(inputs) == 0 {
		return nil, errors.New("no input files found")
	}
	return inputs, nil
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// parseInterspersed parses flags anywhere among positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			pos = append(pos, arg)
			continue
		}
		name := strings.TrimLeft(arg, "-")
		value := ""
		hasValue := false
		if idx := strings.IndexByte(name, '='); idx >= 0 {
			value = name[idx+1:]
			name = name[:idx]
			hasValue = true
		}
		if name == "help" || name == "h" {
			return nil, flag.ErrHelp
		}
		f := fs.Lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown flag -%s", name)
		}
		if hasValue {
			if err := fs.Set(name, value); err != nil {
				return nil, err
			}
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			if err := fs.Set(name, "true"); err != nil {
				return nil, err
			}
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag -%s needs a value", name)
		}
		i++
		if err := fs.Set(name, args[i]); err != nil {
			return nil, err
		}
	}
	return pos, nil
}
