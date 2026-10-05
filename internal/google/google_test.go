package google

import (
	"regexp"
	"strings"
	"testing"

	"github.com/JA3G3R/agneyastra/internal/report"
)

// liveGoogleKeyRE is the shape of a real, usable Google API key — the exact
// pattern todos/agneyastra.md's 2026-08-18 entry says must never survive
// redaction in a blast_radius[] poc.
var liveGoogleKeyRE = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

// TestGETPoCEmbedsLiveKeyButIsRedactable locks in the precondition the
// 2026-08-18 bug was about — poc(), which Scan() uses to build every
// blast_radius[] entry, bakes the literal key into the URL it's given,
// because that IS the request that was actually sent (google.go:37 replaces
// "{KEY}" with the real apiKey before poc() ever sees the URL) — and proves
// the fix: report.RedactPoCs, applied to this real builder's real output (not
// a hand-written stand-in for it), removes the live key.
func TestGETPoCEmbedsLiveKeyButIsRedactable(t *testing.T) {
	rawKey := "AIza" + strings.Repeat("Q", 35)
	const masked = "AIzaQQQQ...QQQQ"

	ep := endpoint{name: "Geocoding", method: "GET"}
	url := strings.ReplaceAll("https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={KEY}", "{KEY}", rawKey)
	got := poc(ep, url)

	if !strings.Contains(got, rawKey) {
		t.Fatalf("precondition failed: poc() no longer embeds the raw key verbatim (update this test to match the code change) — got %s", got)
	}
	if !liveGoogleKeyRE.MatchString(got) {
		t.Fatalf("precondition failed: poc() output doesn't look like it carries a live key at all — got %s", got)
	}

	brs := []report.BlastRadiusEntry{{PoC: got}}
	report.RedactPoCs(nil, brs, rawKey, masked)

	if liveGoogleKeyRE.MatchString(brs[0].PoC) {
		t.Fatalf("blast_radius poc still carries a live-shaped key after redaction: %s", brs[0].PoC)
	}
	if !strings.Contains(brs[0].PoC, masked) {
		t.Fatalf("blast_radius poc should carry the masked form after redaction, got %s", brs[0].PoC)
	}
}

// TestPOSTPoCEmbedsLiveKeyButIsRedactable covers the other shape poc() can
// build — a POST endpoint with a Content-Type/body (e.g. Geolocation,
// Routes, Address Validation) — where the key is still a query param on the
// URL even though the body is not.
func TestPOSTPoCEmbedsLiveKeyButIsRedactable(t *testing.T) {
	rawKey := "AIza" + strings.Repeat("R", 35)
	const masked = "AIzaRRRR...RRRR"

	ep := endpoint{
		name: "Geolocation", method: "POST", contentType: "application/json",
		body: `{"considerIp":true}`,
	}
	url := strings.ReplaceAll("https://www.googleapis.com/geolocation/v1/geolocate?key={KEY}", "{KEY}", rawKey)
	got := poc(ep, url)

	if !strings.Contains(got, rawKey) {
		t.Fatalf("precondition failed: POST poc() no longer embeds the raw key verbatim — got %s", got)
	}

	brs := []report.BlastRadiusEntry{{PoC: got}}
	report.RedactPoCs(nil, brs, rawKey, masked)

	if liveGoogleKeyRE.MatchString(brs[0].PoC) {
		t.Fatalf("POST blast_radius poc still carries a live-shaped key after redaction: %s", brs[0].PoC)
	}
	if !strings.Contains(brs[0].PoC, masked) {
		t.Fatalf("POST blast_radius poc should carry the masked form after redaction, got %s", brs[0].PoC)
	}
}
