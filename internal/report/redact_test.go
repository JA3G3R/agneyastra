package report

import (
	"regexp"
	"strings"
	"testing"
)

// liveGoogleKeyRE is the shape of a real, usable Google API key. After
// RedactPoCs runs (the default, non---show-key path) this must never match
// anywhere in a Finding/BlastRadiusEntry's PoC or Detail — that was exactly
// the 2026-08-18 bug (todos/agneyastra.md): poc always carried the live key
// regardless of --show-key, even though api_key/api_key_masked already
// respected it.
var liveGoogleKeyRE = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

func TestRedactPoCsStripsLiveKeyByDefault(t *testing.T) {
	raw := "AIza" + strings.Repeat("X", 35) // well-formed shape, obviously-fake value
	const masked = "AIzaXXXX...XXXX"

	fs := []Finding{
		{PoC: "curl 'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=" + raw + "'"},
		{
			PoC:    "curl 'https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/users?key=" + raw + "'",
			Detail: "confirmed with key " + raw,
		},
		{PoC: "curl 'https://firebasestorage.googleapis.com/v0/b/p.appspot.com/o'"}, // no key at all -> must be untouched
	}
	brs := []BlastRadiusEntry{
		{PoC: "curl 'https://translation.googleapis.com/language/translate/v2/languages?key=" + raw + "'"},
	}

	RedactPoCs(fs, brs, raw, masked)

	for i, f := range fs {
		if liveGoogleKeyRE.MatchString(f.PoC) {
			t.Errorf("finding %d PoC still carries a live-shaped key: %s", i, f.PoC)
		}
		if liveGoogleKeyRE.MatchString(f.Detail) {
			t.Errorf("finding %d Detail still carries a live-shaped key: %s", i, f.Detail)
		}
	}
	if !strings.Contains(fs[0].PoC, masked) {
		t.Errorf("finding 0 PoC should carry the masked form, got %s", fs[0].PoC)
	}
	if !strings.Contains(fs[1].Detail, masked) {
		t.Errorf("finding 1 Detail should carry the masked form, got %s", fs[1].Detail)
	}
	const untouched = "curl 'https://firebasestorage.googleapis.com/v0/b/p.appspot.com/o'"
	if fs[2].PoC != untouched {
		t.Errorf("finding without a key must be left byte-identical, got %q", fs[2].PoC)
	}
	if liveGoogleKeyRE.MatchString(brs[0].PoC) {
		t.Errorf("blast_radius PoC still carries a live-shaped key: %s", brs[0].PoC)
	}
	if !strings.Contains(brs[0].PoC, masked) {
		t.Errorf("blast_radius PoC should carry the masked form, got %s", brs[0].PoC)
	}
}

// TestRedactPoCsNoopWhenRawEqualsMasked documents the guard scanner relies on
// implicitly not needing: RedactPoCs is safe to call with rawKey==masked
// (a plain no-op), so callers never need a special case for "nothing to hide".
func TestRedactPoCsNoopWhenRawEqualsMasked(t *testing.T) {
	raw := "AIza" + strings.Repeat("Y", 35)
	fs := []Finding{{PoC: "curl '...?key=" + raw + "'"}}
	RedactPoCs(fs, nil, raw, raw)
	if !strings.Contains(fs[0].PoC, raw) {
		t.Fatalf("rawKey==masked must be a no-op, got %s", fs[0].PoC)
	}
}

// TestRedactPoCsEmptyKeyIsNoop guards the classic Go footgun:
// strings.ReplaceAll(s, "", x) inserts x between every rune of s, which would
// corrupt every PoC/Detail string instead of protecting them if rawKey were
// ever empty (e.g. a caller forgetting to pass a key).
func TestRedactPoCsEmptyKeyIsNoop(t *testing.T) {
	fs := []Finding{{PoC: "curl 'https://example.com/'", Detail: "some detail"}}
	origPoC, origDetail := fs[0].PoC, fs[0].Detail
	RedactPoCs(fs, nil, "", "MASKED")
	if fs[0].PoC != origPoC || fs[0].Detail != origDetail {
		t.Fatalf("empty rawKey must be a true no-op, got PoC=%q Detail=%q", fs[0].PoC, fs[0].Detail)
	}
}

// TestRedactPoCsMultipleOccurrences covers a PoC/Detail string that mentions
// the key more than once (defensive: none of today's builders do this, but
// the fix must not assume a single occurrence).
func TestRedactPoCsMultipleOccurrences(t *testing.T) {
	raw := "AIza" + strings.Repeat("Z", 35)
	const masked = "AIzaZZZZ...ZZZZ"
	fs := []Finding{{PoC: raw + " and again " + raw}}
	RedactPoCs(fs, nil, raw, masked)
	if liveGoogleKeyRE.MatchString(fs[0].PoC) {
		t.Fatalf("all occurrences must be redacted, got %s", fs[0].PoC)
	}
	if strings.Count(fs[0].PoC, masked) != 2 {
		t.Fatalf("expected both occurrences masked, got %q", fs[0].PoC)
	}
}
