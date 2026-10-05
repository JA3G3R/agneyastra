package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/JA3G3R/agneyastra/internal/report"
)

// liveGoogleKeyRE mirrors the exact acceptance criterion from
// todos/agneyastra.md's 2026-08-18 entry: after the fix, poc must never
// contain a raw, live-shaped Google API key in the default (no --show-key)
// path.
var liveGoogleKeyRE = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

// TestRedactKeyResultDefaultMasksFindingsAndBlastRadius reproduces the exact
// bug shape: a KeyResult whose findings[].poc and blast_radius[].poc both
// carry the live key (as google.Scan and firebase.Firestore's real PoC
// builders do), scanned with the default (no --show-key) config. It must come
// out with the key stripped from both, mirroring how api_key/api_key_masked
// already behaved.
func TestRedactKeyResultDefaultMasksFindingsAndBlastRadius(t *testing.T) {
	rawKey := "AIza" + strings.Repeat("M", 35)
	kr := report.KeyResult{
		APIKeyMasked: maskKey(rawKey),
		Findings: []report.Finding{
			{Service: "firebase.firestore", Check: "read",
				PoC: "curl 'https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/users?key=" + rawKey + "'"},
		},
		BlastRadius: []report.BlastRadiusEntry{
			{API: "Geocoding", PoC: "curl 'https://maps.googleapis.com/maps/api/geocode/json?key=" + rawKey + "'"},
		},
	}

	out := redactKeyResult(kr, rawKey, false)

	if liveGoogleKeyRE.MatchString(out.Findings[0].PoC) {
		t.Fatalf("default (no --show-key) run must not leak the raw key in findings[].poc: %s", out.Findings[0].PoC)
	}
	if liveGoogleKeyRE.MatchString(out.BlastRadius[0].PoC) {
		t.Fatalf("default (no --show-key) run must not leak the raw key in blast_radius[].poc: %s", out.BlastRadius[0].PoC)
	}
	if !strings.Contains(out.Findings[0].PoC, out.APIKeyMasked) {
		t.Fatalf("expected the masked key in findings[].poc, got %s", out.Findings[0].PoC)
	}
	if !strings.Contains(out.BlastRadius[0].PoC, out.APIKeyMasked) {
		t.Fatalf("expected the masked key in blast_radius[].poc, got %s", out.BlastRadius[0].PoC)
	}
}

// TestRedactKeyResultShowKeyLeavesRawKeyIntact locks in the other half of the
// contract: --show-key must still yield a live, directly-runnable PoC,
// exactly like it already does for api_key.
func TestRedactKeyResultShowKeyLeavesRawKeyIntact(t *testing.T) {
	rawKey := "AIza" + strings.Repeat("N", 35)
	kr := report.KeyResult{
		APIKeyMasked: maskKey(rawKey),
		Findings:     []report.Finding{{PoC: "curl '...?key=" + rawKey + "'"}},
	}

	out := redactKeyResult(kr, rawKey, true) // --show-key

	if !strings.Contains(out.Findings[0].PoC, rawKey) {
		t.Fatalf("--show-key must leave the live key in poc (mirrors api_key/api_key_masked), got %s", out.Findings[0].PoC)
	}
}
