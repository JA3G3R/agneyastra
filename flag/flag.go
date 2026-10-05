// Package flags defines the agneyastra command-line interface and translates it
// into a scanner.Config. The root command scans all services; the bucket / rtdb
// / firestore / auth / google subcommands scan just one family. Everything is
// driven through the single scanner engine.
package flags

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JA3G3R/agneyastra/internal/config"
	"github.com/JA3G3R/agneyastra/internal/correlation"
	"github.com/JA3G3R/agneyastra/internal/firebase"
	"github.com/JA3G3R/agneyastra/internal/report"
	"github.com/JA3G3R/agneyastra/internal/scanner"
	"github.com/JA3G3R/agneyastra/internal/secrets"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is the tool version, overridable at build time via -ldflags.
var Version = "2.0.0"

var (
	apiKey         string
	apiKeyFile     string
	projectIDsFlag string
	configPath     string

	active      bool
	verbose     bool
	showKey     bool
	concurrency int
	timeoutSec  int

	outputFmt    string
	outPath      string
	reportHTML   string
	templateFile string

	secretsExtract   bool
	secretsRegexFile string
	correlate        bool
	pentestData      string

	// auth inputs (also settable via config.yaml)
	signupEmail    string
	signupPassword string
	customToken    string
	userEmail      string
	userPassword   string
	sendLinkEmail  string
)

// RootCmd scans every service by default.
var RootCmd = &cobra.Command{
	Use:   "agneyastra",
	Short: "Assess the blast radius of a Google/Firebase API key",
	Long: `Agneyastra checks a Google/Firebase API key against Firebase services
(Auth, Firestore, Realtime Database, Cloud Storage) and against every Google API
that accepts a bare API key (Maps Platform, Gemini, Translation, YouTube, and
more). Reads and existence checks run by default; write/delete probes require
--active.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initConfig()
		if apiKey == "" && apiKeyFile == "" {
			return fmt.Errorf("provide an API key with --key, or a file of keys with --key-file (use '-' for stdin)")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(scanner.AllServices())
	},
}

func serviceCmd(use, short string, svc scanner.Services) *cobra.Command {
	return &cobra.Command{
		Use:           use,
		Short:         short,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(svc)
		},
	}
}

// Execute runs the CLI.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	pf := RootCmd.PersistentFlags()
	pf.StringVar(&apiKey, "key", "", "Google/Firebase API key")
	pf.StringVar(&apiKeyFile, "key-file", "", "File of API keys, one per line as `key[,projectID,...]` ('-' = stdin)")
	pf.StringVar(&projectIDsFlag, "project-id", "", "Comma-separated project IDs to test (for a single --key)")
	pf.StringVar(&configPath, "config", "", "Custom config file path")

	pf.BoolVar(&active, "active", false, "Enable state-changing probes (write/delete, send sign-in email). Off by default")
	pf.BoolVarP(&verbose, "verbose", "v", false, "Include safe/not-applicable results in output")
	pf.BoolVar(&showKey, "show-key", false, "Include the full API key (not just a masked form) in output")
	pf.IntVar(&concurrency, "concurrency", 0, "Number of keys scanned in parallel (0 = auto)")
	pf.IntVar(&timeoutSec, "timeout", 15, "Per-request timeout in seconds")

	pf.StringVarP(&outputFmt, "output", "o", "json", "stdout format: json | table | html")
	pf.StringVar(&outPath, "out", "", "Write the chosen output to this file instead of stdout")
	pf.StringVar(&reportHTML, "report-html", "", "Additionally write a standalone HTML report to this path")
	pf.StringVar(&templateFile, "template-file", "", "Custom HTML template (defaults to the embedded one)")

	pf.BoolVar(&secretsExtract, "secrets-extract", false, "Scan recovered data for secrets")
	pf.StringVar(&secretsRegexFile, "secrets-regex-file", "", "Custom secret regexes (JSON/YAML map name->pattern)")
	pf.BoolVar(&correlate, "correlate", false, "Score recovered data against a target profile")
	pf.StringVar(&pentestData, "pentest-data", "", "Target profile JSON for --correlate")

	pf.StringVar(&signupEmail, "signup-email", "", "Email for the sign-up probe (default: random)")
	pf.StringVar(&signupPassword, "signup-password", "", "Password for the sign-up probe (default: random)")
	pf.StringVar(&customToken, "custom-token", "", "Firebase custom JWT to test custom-token sign-in")
	pf.StringVar(&userEmail, "user-email", "", "Existing account email to test privileged access")
	pf.StringVar(&userPassword, "user-password", "", "Existing account password to test privileged access")
	pf.StringVar(&sendLinkEmail, "send-link-email", "", "Address for the email-link probe (--active only)")

	RootCmd.AddCommand(
		serviceCmd("bucket", "Cloud Storage checks only", scanner.Services{Auth: true, Storage: true}),
		serviceCmd("rtdb", "Realtime Database checks only", scanner.Services{Auth: true, RTDB: true}),
		serviceCmd("firestore", "Cloud Firestore checks only", scanner.Services{Auth: true, Firestore: true}),
		serviceCmd("auth", "Auth provider checks only", scanner.Services{Auth: true}),
		serviceCmd("google", "Generic Google API blast-radius checks only", scanner.Services{Google: true}),
	)
	RootCmd.CompletionOptions.DisableDefaultCmd = true
}

func initConfig() {
	viper.SetConfigType("yaml")
	_ = viper.ReadConfig(bytes.NewReader(config.DefaultConfigYAML))

	path := configPath
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".config", "agneyastra", "config.yaml")
			ensureUserConfig(path)
		}
	}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = viper.MergeConfig(bytes.NewReader(data))
		}
	}
}

// ensureUserConfig writes the embedded default config to path if absent. This is
// a local convenience only — nothing is fetched over the network.
func ensureUserConfig(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, config.DefaultConfigYAML, 0o644)
}

func runScan(svc scanner.Services) error {
	keys, err := loadKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no API keys to scan")
	}

	cfg := scanner.Config{
		Keys:           keys,
		Active:         active,
		Concurrency:    concurrency,
		RequestTimeout: time.Duration(timeoutSec) * time.Second,
		Services:       svc,
		ShowKey:        showKey,
		Version:        Version,
		Auth: firebase.AuthConfig{
			SignupEmail:    orConfig(signupEmail, "auth.signup.email"),
			SignupPassword: orConfig(signupPassword, "auth.signup.password"),
			CustomToken:    orConfig(customToken, "auth.custom-token.token"),
			UserEmail:      orConfig(userEmail, "auth.user.email"),
			UserPassword:   orConfig(userPassword, "auth.user.password"),
			SendLinkEmail:  orConfig(sendLinkEmail, "auth.send-link.email"),
		},
	}

	if secretsExtract {
		compiled, err := secrets.Compile(secretsRegexFile)
		if err != nil {
			return fmt.Errorf("loading secret regexes: %w", err)
		}
		cfg.SecretsExtract = true
		cfg.SecretRegexes = compiled
	}
	if correlate {
		if pentestData == "" {
			return fmt.Errorf("--correlate requires --pentest-data")
		}
		in, err := correlation.Load(pentestData)
		if err != nil {
			return fmt.Errorf("loading pentest data: %w", err)
		}
		cfg.Correlate = true
		cfg.PentestInput = in
	}

	res := scanner.Run(context.Background(), cfg)
	return emit(res.Report)
}

func emit(rep *report.Report) error {
	var w io.Writer = os.Stdout
	var closer io.Closer
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		w, closer = f, f
	}

	var renderErr error
	switch strings.ToLower(outputFmt) {
	case "table":
		renderErr = rep.RenderTable(w, verbose)
	case "html":
		renderErr = rep.RenderHTML(w, verbose, templateFile)
	default:
		renderErr = rep.RenderJSON(w, verbose)
	}
	if closer != nil {
		_ = closer.Close()
	}
	if renderErr != nil {
		return renderErr
	}

	if reportHTML != "" {
		if err := rep.WriteHTMLFile(reportHTML, verbose, templateFile); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "HTML report written to", reportHTML)
	}
	return nil
}

func orConfig(flagVal, viperKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return viper.GetString(viperKey)
}

func loadKeys() ([]scanner.KeyInput, error) {
	if apiKey != "" {
		var pids []string
		for _, p := range strings.Split(projectIDsFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pids = append(pids, p)
			}
		}
		return []scanner.KeyInput{{Key: apiKey, ProjectIDs: pids}}, nil
	}
	return readKeyFile(apiKeyFile)
}

func readKeyFile(path string) ([]scanner.KeyInput, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	var keys []scanner.KeyInput
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		key := strings.TrimSpace(parts[0])
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		var pids []string
		for _, p := range parts[1:] {
			if p = strings.TrimSpace(p); p != "" {
				pids = append(pids, p)
			}
		}
		keys = append(keys, scanner.KeyInput{Key: key, ProjectIDs: pids})
	}
	return keys, sc.Err()
}
