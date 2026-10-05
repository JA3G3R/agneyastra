// Package report defines the output schema for agneyastra and renders it as
// JSON, a terminal table, or an HTML document. The schema is deliberately flat
// and triage-friendly: one Report per run, one KeyResult per API key, and a
// flat list of Findings per key sorted by severity.
package report

import (
	"sort"
	"sync"
)

// Severity ranks a finding's impact.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank returns a sortable weight (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

// Status is the outcome of a single check against a single resource.
type Status string

const (
	// StatusVulnerable: access was actually obtained (a real finding).
	StatusVulnerable Status = "vulnerable"
	// StatusSafe: the resource exists but access was correctly denied.
	StatusSafe Status = "safe"
	// StatusNotApplicable: the resource does not exist or the service is
	// disabled for this project. This is the state that used to be mis-reported
	// as vulnerable for legacy numeric project IDs.
	StatusNotApplicable Status = "not_applicable"
	// StatusNotTested: the check could not be run safely (e.g. a delete probe
	// that needs write access we don't have) — recorded, never a finding.
	StatusNotTested Status = "not_tested"
	// StatusError: the check failed for an operational reason (network, parse).
	StatusError Status = "error"
)

// Confidence expresses how sure we are that the finding is real and exploitable.
type Confidence string

const (
	ConfConfirmed Confidence = "confirmed" // we performed the action successfully
	ConfProbable  Confidence = "probable"
	ConfPossible  Confidence = "possible"
)

// Auth levels, in ascending order of privilege required by an attacker. The
// lowest level that unlocks a resource is the most severe, because it is the
// easiest to abuse.
const (
	AuthPublic    = "public"
	AuthAnon      = "anon"
	AuthSignup    = "signup"
	AuthCustom    = "custom-token"
	AuthUserCreds = "user-creds"
)

// Finding is a single access result worth reporting.
type Finding struct {
	Service     string         `json:"service"`            // e.g. "firebase.storage", "firebase.firestore"
	Check       string         `json:"check"`              // "read" | "list" | "write" | "delete" | "provider"
	Resource    string         `json:"resource,omitempty"` // bucket / rtdb host / project id
	Access      string         `json:"access,omitempty"`   // auth level that unlocked it
	Status      Status         `json:"status"`
	Severity    Severity       `json:"severity"`
	Confidence  Confidence     `json:"confidence,omitempty"`
	Title       string         `json:"title"`
	Detail      string         `json:"detail,omitempty"`
	AuthChain   []string       `json:"auth_chain,omitempty"` // e.g. ["anon"] meaning anon token unlocked it
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	PoC         string         `json:"poc,omitempty"`
}

// BlastRadiusEntry is one Google API tested against the key.
type BlastRadiusEntry struct {
	API         string   `json:"api"`
	Category    string   `json:"category"` // maps | messaging | genai | translation | youtube | safebrowsing | search
	Enabled     bool     `json:"enabled"`  // key is unrestricted for this API
	Severity    Severity `json:"severity,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	PoC         string   `json:"poc,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Project is a resolved project identity for the key.
type Project struct {
	ID        string `json:"id"`
	Number    string `json:"number,omitempty"`
	IDSource  string `json:"id_source,omitempty"` // authorized_domain | user_supplied | api_response
	Numeric   bool   `json:"numeric,omitempty"`   // true if ID is a bare project number (untrustworthy for URLs)
	Validated bool   `json:"validated"`           // at least one real resource confirmed to exist
}

// AuthProviders records which Firebase Auth sign-in methods are enabled.
type AuthProviders struct {
	Anonymous           bool `json:"anonymous"`
	EmailPasswordSignup bool `json:"email_password_signup"`
	EmailLink           bool `json:"email_link"`
	CustomToken         bool `json:"custom_token"`
	PasswordSignin      bool `json:"password_signin,omitempty"`
}

// KeyResult holds everything discovered for one API key.
type KeyResult struct {
	APIKey            string                         `json:"api_key,omitempty"` // only populated with --show-key
	APIKeyMasked      string                         `json:"api_key_masked"`
	KeyFormat         string                         `json:"key_format"` // google_api_key | unknown
	Valid             bool                           `json:"valid"`
	Projects          []Project                      `json:"projects,omitempty"`
	AuthorizedDomains []string                       `json:"authorized_domains,omitempty"`
	AuthProviders     *AuthProviders                 `json:"auth_providers,omitempty"`
	Findings          []Finding                      `json:"findings"`
	BlastRadius       []BlastRadiusEntry             `json:"blast_radius,omitempty"`
	CorrelationScore  float64                        `json:"correlation_score,omitempty"`
	Secrets           map[string]map[string][]string `json:"secrets,omitempty"`
	Errors            []string                       `json:"errors,omitempty"`
}

// ScanMeta describes the run itself.
type ScanMeta struct {
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	DurationMS  int64  `json:"duration_ms"`
	ActiveMode  bool   `json:"active_mode"`
	KeysScanned int    `json:"keys_scanned"`
}

// Summary aggregates counts across all keys.
type Summary struct {
	Findings           int            `json:"findings"`
	VulnerableKeys     int            `json:"vulnerable_keys"`
	BySeverity         map[string]int `json:"by_severity"`
	ByService          map[string]int `json:"by_service"`
	BlastRadiusEnabled int            `json:"blast_radius_enabled"`
}

// Report is the top-level document.
type Report struct {
	Tool    string      `json:"tool"`
	Version string      `json:"version"`
	Scan    ScanMeta    `json:"scan"`
	Results []KeyResult `json:"results"`
	Summary Summary     `json:"summary"`

	mu sync.Mutex `json:"-"`
}

// AddResult appends a KeyResult in a concurrency-safe way.
func (r *Report) AddResult(kr KeyResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Results = append(r.Results, kr)
}

// Finalize sorts findings, orders results deterministically, and computes the
// summary. Call once after all keys are scanned.
func (r *Report) Finalize() {
	r.mu.Lock()
	defer r.mu.Unlock()

	sum := Summary{BySeverity: map[string]int{}, ByService: map[string]int{}}

	for i := range r.Results {
		kr := &r.Results[i]
		SortFindings(kr.Findings)

		keyHasVuln := false
		for _, f := range kr.Findings {
			if f.Status != StatusVulnerable {
				continue
			}
			keyHasVuln = true
			sum.Findings++
			sum.BySeverity[string(f.Severity)]++
			sum.ByService[f.Service]++
		}
		if keyHasVuln {
			sum.VulnerableKeys++
		}
		for _, b := range kr.BlastRadius {
			if b.Enabled {
				sum.BlastRadiusEnabled++
			}
		}
	}

	// Deterministic result order: most-vulnerable keys first, then by masked key.
	sort.SliceStable(r.Results, func(i, j int) bool {
		si, sj := topSeverityRank(r.Results[i]), topSeverityRank(r.Results[j])
		if si != sj {
			return si > sj
		}
		return r.Results[i].APIKeyMasked < r.Results[j].APIKeyMasked
	})

	r.Summary = sum
}

// SortFindings orders findings by severity (desc), then vulnerable-before-other,
// then service/check for stability.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		vi, vj := fs[i].Status == StatusVulnerable, fs[j].Status == StatusVulnerable
		if vi != vj {
			return vi
		}
		if fs[i].Service != fs[j].Service {
			return fs[i].Service < fs[j].Service
		}
		return fs[i].Check < fs[j].Check
	})
}

func topSeverityRank(kr KeyResult) int {
	best := 0
	for _, f := range kr.Findings {
		if f.Status == StatusVulnerable && f.Severity.Rank() > best {
			best = f.Severity.Rank()
		}
	}
	return best
}
