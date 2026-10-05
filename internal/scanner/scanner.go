// Package scanner is the orchestrator. It fans a bounded worker pool across the
// input keys, and for each key runs the identity resolution, the (per-key) auth
// stage, the existence-gated Firebase service checks, and the Google
// blast-radius sweep — most of it concurrently — then assembles one KeyResult.
package scanner

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/JA3G3R/agneyastra/internal/correlation"
	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/firebase"
	"github.com/JA3G3R/agneyastra/internal/google"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/keyinfo"
	"github.com/JA3G3R/agneyastra/internal/report"
	"github.com/JA3G3R/agneyastra/internal/secrets"
)

// KeyInput is one API key and any project IDs the operator supplied for it.
type KeyInput struct {
	Key        string
	ProjectIDs []string
}

// Services selects which check families run.
type Services struct {
	Auth      bool
	Storage   bool
	RTDB      bool
	Firestore bool
	Google    bool
}

// AllServices returns a Services with everything enabled.
func AllServices() Services {
	return Services{Auth: true, Storage: true, RTDB: true, Firestore: true, Google: true}
}

// Config drives a run.
type Config struct {
	Keys           []KeyInput
	Active         bool
	Concurrency    int
	RequestTimeout time.Duration
	Auth           firebase.AuthConfig
	Services       Services
	ShowKey        bool
	Version        string

	// Optional post-processing over data dumped from readable resources.
	SecretsExtract bool
	SecretRegexes  map[string]*regexp.Regexp
	Correlate      bool
	PentestInput   *correlation.Input
}

// RunResult bundles the report with the raw data dumped from readable
// RTDB/Storage resources, for the optional secrets/correlation stages.
type RunResult struct {
	Report *report.Report
	// Dumps maps API key -> resource -> raw body.
	Dumps map[string]map[string][]byte
}

// Run executes the scan described by cfg.
func Run(ctx context.Context, cfg Config) *RunResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = min(8, max(1, len(cfg.Keys)))
	}
	client := httpx.New(cfg.RequestTimeout)
	started := time.Now()

	rep := &report.Report{
		Tool:    "agneyastra",
		Version: cfg.Version,
	}
	dumps := map[string]map[string][]byte{}
	var dumpMu sync.Mutex

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for _, in := range cfg.Keys {
		wg.Add(1)
		go func(in KeyInput) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			kr, kd := scanKey(ctx, client, cfg, in)
			rep.AddResult(kr)
			if len(kd) > 0 {
				dumpMu.Lock()
				dumps[in.Key] = kd
				dumpMu.Unlock()
			}
		}(in)
	}
	wg.Wait()

	fin := time.Now()
	rep.Scan = report.ScanMeta{
		StartedAt:   started.UTC().Format(time.RFC3339),
		FinishedAt:  fin.UTC().Format(time.RFC3339),
		DurationMS:  fin.Sub(started).Milliseconds(),
		ActiveMode:  cfg.Active,
		KeysScanned: len(cfg.Keys),
	}
	rep.Finalize()
	return &RunResult{Report: rep, Dumps: dumps}
}

func scanKey(ctx context.Context, client *httpx.Client, cfg Config, in KeyInput) (report.KeyResult, map[string][]byte) {
	info := keyinfo.Resolve(ctx, client, in.Key, in.ProjectIDs)

	kr := report.KeyResult{
		APIKeyMasked:      maskKey(in.Key),
		KeyFormat:         info.Format,
		Valid:             info.Valid,
		Projects:          info.Projects,
		AuthorizedDomains: info.AuthorizedDomains,
		Errors:            info.Errors,
	}
	if cfg.ShowKey {
		kr.APIKey = in.Key
	}

	// Per-key credentials (never shared across keys).
	cs := creds.New()
	if cfg.Services.Auth {
		set, providers, findings, errs := firebase.Auth(ctx, client, in.Key, cfg.Auth, cfg.Active)
		cs = set
		kr.AuthProviders = providers
		kr.Findings = append(kr.Findings, findings...)
		kr.Errors = append(kr.Errors, errs...)
	}

	dumps := map[string][]byte{}

	// Firebase resource checks run per resolved project, concurrently. Numeric
	// project numbers flow through too, but the existence probes turn them into
	// not_applicable rather than false positives.
	type svc struct {
		on bool
		fn func(context.Context, *httpx.Client, string, string, *creds.Set, bool) firebase.Result
	}
	svcs := []svc{
		{cfg.Services.Storage, firebase.Storage},
		{cfg.Services.RTDB, firebase.RTDB},
		{cfg.Services.Firestore, firebase.Firestore},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	validated := map[string]bool{}

	for pi := range info.Projects {
		pid := info.Projects[pi].ID
		for _, s := range svcs {
			if !s.on {
				continue
			}
			wg.Add(1)
			go func(pid string, fn func(context.Context, *httpx.Client, string, string, *creds.Set, bool) firebase.Result) {
				defer wg.Done()
				res := fn(ctx, client, in.Key, pid, cs, cfg.Active)
				mu.Lock()
				kr.Findings = append(kr.Findings, res.Findings...)
				if res.Existed {
					validated[pid] = true
				}
				for k, v := range res.Dumps {
					dumps[k] = v
				}
				mu.Unlock()
			}(pid, s.fn)
		}
	}

	// Google blast radius (independent of project id) runs alongside.
	if cfg.Services.Google {
		wg.Add(1)
		go func() {
			defer wg.Done()
			br := google.Scan(ctx, client, in.Key)
			mu.Lock()
			kr.BlastRadius = append(kr.BlastRadius, br...)
			if len(br) > 0 {
				kr.Valid = true // a working Google API proves the key is live
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	kr = redactKeyResult(kr, in.Key, cfg.ShowKey)

	// Optional post-processing over the recovered data.
	if len(dumps) > 0 {
		if cfg.SecretsExtract && len(cfg.SecretRegexes) > 0 {
			found := map[string]map[string][]string{}
			for resource, blob := range dumps {
				svc := resource
				if i := strings.IndexByte(resource, ':'); i > 0 {
					svc = resource[:i] // "rtdb:host" -> "rtdb"
				}
				if s := secrets.Extract(cfg.SecretRegexes, blob); len(s) > 0 {
					if found[svc] == nil {
						found[svc] = map[string][]string{}
					}
					for t, matches := range s {
						found[svc][t] = append(found[svc][t], matches...)
					}
				}
			}
			if len(found) > 0 {
				kr.Secrets = found
			}
		}
		if cfg.Correlate && cfg.PentestInput != nil {
			blobs := make([][]byte, 0, len(dumps))
			for _, b := range dumps {
				blobs = append(blobs, b)
			}
			kr.CorrelationScore = correlation.Score(cfg.PentestInput, blobs)
		}
	}

	for i := range kr.Projects {
		if validated[kr.Projects[i].ID] {
			kr.Projects[i].Validated = true
		}
	}
	if len(info.Projects) == 0 {
		kr.Errors = append(kr.Errors, "no resolvable string project ID (only a numeric project number, or none, was available); Firebase resource checks were skipped to avoid false positives")
	}
	return kr, dumps
}

func maskKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:8] + "..." + k[len(k)-4:]
}

// redactKeyResult strips the live API key out of every PoC/Detail string in
// kr unless showKey is set, replacing it with kr's already-computed masked
// form (APIKeyMasked). It runs once per key, after every finding — auth, the
// per-project Firebase service checks, and the Google blast-radius sweep —
// has been collected (see the wg.Wait() call site above), so it is the
// single point that guarantees a raw key can reach the default report only
// through the api_key/api_key_masked pair's own --show-key gate, never
// through a poc string, regardless of which package (google/firebase/…)
// built that string, or whether a future one repeats the pattern.
//
// Fixes todos/agneyastra.md 2026-08-18: poc previously carried the live key
// unconditionally, because it is built from the literal HTTP request that was
// actually sent (google.go's blast-radius sweep, firestore.go's read PoC both
// embed apiKey as a `?key=` query param) — contradicting the tool's own
// implied contract that non---show-key output is safe to read/paste in full.
func redactKeyResult(kr report.KeyResult, rawKey string, showKey bool) report.KeyResult {
	if showKey {
		return kr
	}
	report.RedactPoCs(kr.Findings, kr.BlastRadius, rawKey, kr.APIKeyMasked)
	return kr
}
