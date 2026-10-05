// Package keyinfo resolves the identity behind a Google/Firebase API key.
//
// The single most important job here is producing *trustworthy* project IDs.
// The legacy Identity Toolkit config endpoint returns the numeric project
// *number* as "projectId" for older projects. The previous version of the tool
// fed that number straight into resource URLs like `<number>.appspot.com` and
// `<number>-default-rtdb.firebaseio.com`, which never exist — and then reported
// the resulting 404s as vulnerabilities. We instead derive the real string
// project ID from the authorized domains (`<id>.firebaseapp.com` /
// `<id>.web.app`) and keep the numeric value as metadata only.
package keyinfo

import (
	"context"
	"regexp"
	"strings"

	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

// googleKeyRE matches the canonical browser API key format (AIza + 35 chars).
var googleKeyRE = regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`)

var numericRE = regexp.MustCompile(`^\d+$`)

// Info is the resolved identity for one API key.
type Info struct {
	APIKey            string
	Format            string // "google_api_key" | "unknown"
	Valid             bool   // key accepted by at least one Google endpoint
	Number            string // numeric project number, metadata only
	AuthorizedDomains []string
	Projects          []report.Project // candidate string project IDs
	Errors            []string
}

type configResp struct {
	ProjectID         string   `json:"projectId"`
	AuthorizedDomains []string `json:"authorizedDomains"`
}

type errEnvelope struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// Resolve fetches project configuration for the key and derives its identity.
// userProjectIDs are IDs supplied by the operator (CLI/key-file) and are always
// trusted as string IDs.
func Resolve(ctx context.Context, client *httpx.Client, apiKey string, userProjectIDs []string) *Info {
	info := &Info{APIKey: apiKey, Format: "unknown"}
	if googleKeyRE.MatchString(apiKey) {
		info.Format = "google_api_key"
	}

	cfg, valid, err := fetchProjectConfig(ctx, client, apiKey)
	if err != "" {
		info.Errors = append(info.Errors, err)
	}
	info.Valid = valid

	// idSet preserves insertion order while de-duplicating.
	type candidate struct {
		id, source string
	}
	seen := map[string]bool{}
	var cands []candidate
	add := func(id, source string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		cands = append(cands, candidate{id, source})
	}

	if cfg != nil {
		info.AuthorizedDomains = cfg.AuthorizedDomains
		// Authorized domains are the gold source for the real string project ID.
		for _, id := range projectIDsFromDomains(cfg.AuthorizedDomains) {
			add(id, "authorized_domain")
		}
		// The reported projectId: numeric => keep as Number, string => usable ID.
		if cfg.ProjectID != "" {
			if numericRE.MatchString(cfg.ProjectID) {
				info.Number = cfg.ProjectID
			} else {
				add(cfg.ProjectID, "api_response")
			}
		}
	}

	// Operator-supplied IDs are always trusted (and win an existing source).
	for _, id := range userProjectIDs {
		add(id, "user_supplied")
	}

	for _, c := range cands {
		info.Projects = append(info.Projects, report.Project{
			ID:       c.id,
			Number:   info.Number,
			IDSource: c.source,
			Numeric:  numericRE.MatchString(c.id),
		})
	}
	return info
}

// fetchProjectConfig tries the current v1 endpoint, then the legacy v3 one.
// It returns the parsed config (may be nil), whether the key looks valid, and an
// optional error string.
func fetchProjectConfig(ctx context.Context, client *httpx.Client, apiKey string) (*configResp, bool, string) {
	endpoints := []string{
		"https://identitytoolkit.googleapis.com/v1/projects?key=" + apiKey,
		"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=" + apiKey,
	}
	var lastErr string
	keyInvalid := false
	for _, url := range endpoints {
		resp, err := client.Get(ctx, url, nil)
		if err != nil {
			lastErr = "project config request failed: " + err.Error()
			continue
		}
		switch {
		case resp.Status == 200:
			var cfg configResp
			if err := resp.JSON(&cfg); err != nil {
				lastErr = "failed to parse project config: " + err.Error()
				continue
			}
			return &cfg, true, ""
		case resp.Status == 400 || resp.Status == 401 || resp.Status == 403:
			var e errEnvelope
			_ = resp.JSON(&e)
			msg := e.Error.Status + " " + e.Error.Message
			if isKeyInvalid(resp) {
				keyInvalid = true
				lastErr = "API key rejected: " + strings.TrimSpace(msg)
				continue
			}
			// 403 typically means Identity Toolkit isn't enabled / key is
			// restricted; the key itself may still be valid for other services.
			return nil, true, "identity toolkit not accessible: " + strings.TrimSpace(msg)
		default:
			lastErr = "unexpected project config status"
		}
	}
	if keyInvalid {
		return nil, false, lastErr
	}
	return nil, true, lastErr
}

// isKeyInvalid detects the definitive "this key string is not valid" signal.
func isKeyInvalid(resp *httpx.Response) bool {
	return resp.BodyContains("API_KEY_INVALID") || resp.BodyContains("API key not valid")
}

// projectIDsFromDomains extracts the subdomain label from Firebase-hosted
// authorized domains, which equals the real string project ID.
func projectIDsFromDomains(domains []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		var sub string
		switch {
		case strings.HasSuffix(d, ".firebaseapp.com"):
			sub = strings.TrimSuffix(d, ".firebaseapp.com")
		case strings.HasSuffix(d, ".web.app"):
			sub = strings.TrimSuffix(d, ".web.app")
		default:
			continue
		}
		// Guard against multi-label leftovers; the project ID is a single label.
		if sub == "" || strings.Contains(sub, ".") || seen[sub] {
			continue
		}
		seen[sub] = true
		out = append(out, sub)
	}
	return out
}
