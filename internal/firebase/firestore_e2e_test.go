package firebase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

func withHost(t *testing.T, h http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(h)
	old := firestoreHost
	firestoreHost = srv.URL
	return func() { firestoreHost = old; srv.Close() }
}

func countVuln(res Result) int {
	n := 0
	for _, f := range res.Findings {
		if f.Status == report.StatusVulnerable {
			n++
		}
	}
	return n
}

func runFirestore(active bool) Result {
	return Firestore(context.Background(), httpx.New(2*time.Second), "KEY", "proj", creds.New(), active)
}

// A database that does not exist must NEVER produce a finding — this is the core
// fix for the legacy numeric-project-id false positives.
func TestFirestoreAbsentNeverVulnerable(t *testing.T) {
	defer withHost(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"error":{"status":"NOT_FOUND","message":"database (default) does not exist"}}`))
	})()
	res := runFirestore(true)
	if res.Existed {
		t.Error("absent database must not be marked existed")
	}
	if countVuln(res) != 0 {
		t.Fatalf("absent database produced %d vulnerable findings, want 0", countVuln(res))
	}
}

// Rules that deny access: the resource exists but nothing should be reported as
// vulnerable.
func TestFirestoreDeniedIsSafe(t *testing.T) {
	defer withHost(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED","message":"Missing or insufficient permissions."}}`))
	})()
	res := runFirestore(false)
	if !res.Existed {
		t.Error("denied-but-present database should be marked existed")
	}
	if countVuln(res) != 0 {
		t.Fatalf("denied database produced %d vulnerable findings, want 0", countVuln(res))
	}
}

// Open read + writable + deletable: expect read, write and delete findings, and
// the delete finding must only appear because create-then-delete succeeded.
func TestFirestoreOpenActive(t *testing.T) {
	defer withHost(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "/users") {
				w.WriteHeader(200)
				w.Write([]byte(`{"documents":[{"name":"projects/proj/databases/(default)/documents/users/1"}]}`))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{}`)) // probe collection readable (empty)
		case http.MethodPost:
			w.WriteHeader(200)
			w.Write([]byte(`{"name":"created"}`))
		case http.MethodDelete:
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		}
	})()

	res := runFirestore(true)
	if !res.Existed {
		t.Fatal("open database should be marked existed")
	}
	got := map[string]report.Finding{}
	for _, f := range res.Findings {
		if f.Status == report.StatusVulnerable {
			got[f.Check] = f
		}
	}
	for _, check := range []string{"read", "write", "delete"} {
		if _, ok := got[check]; !ok {
			t.Errorf("expected a vulnerable %q finding", check)
		}
	}
	if got["read"].Severity != report.SevHigh {
		t.Errorf("open read with data should be high, got %s", got["read"].Severity)
	}
}

// TestFirestoreReadPoCEmbedsLiveKeyButIsRedactable locks in the precondition
// the 2026-08-18 bug (todos/agneyastra.md) was about — Firestore's own real
// "read" PoC (firestore.go:71) bakes the literal key into the curl string,
// because that IS the request that was actually sent — and proves the fix:
// report.RedactPoCs, applied to THIS package's real PoC output (not a
// hand-written stand-in for it), removes the live key. The masking itself is
// the caller's (scanner's) job; this only proves Firestore's PoC shape is
// exactly what RedactPoCs expects to find.
func TestFirestoreReadPoCEmbedsLiveKeyButIsRedactable(t *testing.T) {
	defer withHost(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users") {
			w.WriteHeader(200)
			w.Write([]byte(`{"documents":[{"name":"projects/proj/databases/(default)/documents/users/1"}]}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	})()

	rawKey := "AIza" + strings.Repeat("Z", 35)
	const masked = "AIzaZZZZ...ZZZZ"

	res := Firestore(context.Background(), httpx.New(2*time.Second), rawKey, "proj", creds.New(), false)

	readIdx := -1
	for i, f := range res.Findings {
		if f.Check == "read" && f.Status == report.StatusVulnerable {
			readIdx = i
		}
	}
	if readIdx == -1 {
		t.Fatal("expected a vulnerable read finding")
	}
	if !strings.Contains(res.Findings[readIdx].PoC, rawKey) {
		t.Fatalf("precondition failed: Firestore()'s own PoC no longer embeds the raw key verbatim (update this test to match the code change) — got %s", res.Findings[readIdx].PoC)
	}

	// This is the fix under test: scanner.scanKey applies exactly this
	// transformation, using Firestore()'s own real output, before it ever
	// reaches the report unless --show-key was passed.
	report.RedactPoCs(res.Findings, nil, rawKey, masked)

	if strings.Contains(res.Findings[readIdx].PoC, rawKey) {
		t.Fatalf("firestore read PoC still carries the raw key after redaction: %s", res.Findings[readIdx].PoC)
	}
	if !strings.Contains(res.Findings[readIdx].PoC, masked) {
		t.Fatalf("firestore read PoC should carry the masked form after redaction, got %s", res.Findings[readIdx].PoC)
	}
}

// TestFirestoreErrFindingDetailEmbedsLiveKeyButIsRedactable covers a SECOND,
// distinct leak path found while fixing todos/agneyastra.md's 2026-08-18
// entry (not the literal poc string this time): Go's *url.Error.Error()
// embeds the full request URL verbatim on a transport failure — and
// firestore.go's read/write request URLs always carry "?key=<apiKey>" — so
// errFinding's `Detail: err.Error()` can leak the live key exactly like a PoC
// can. This path only surfaces under --verbose (StatusError findings are
// dropped from the default, non-verbose View), but redaction must not depend
// on --verbose, only on --show-key, so RedactPoCs has to (and does) cover
// Detail too, not just PoC.
func TestFirestoreErrFindingDetailEmbedsLiveKeyButIsRedactable(t *testing.T) {
	old := firestoreHost
	firestoreHost = "http://127.0.0.1:1" // nothing listens here -> fast, deterministic connection-refused
	defer func() { firestoreHost = old }()

	rawKey := "AIza" + strings.Repeat("E", 35)
	const masked = "AIzaEEEE...EEEE"

	res := Firestore(context.Background(), httpx.New(2*time.Second), rawKey, "proj", creds.New(), false)

	errIdx := -1
	for i, f := range res.Findings {
		if f.Status == report.StatusError {
			errIdx = i
		}
	}
	if errIdx == -1 {
		t.Fatal("expected an error finding when the firestore host is unreachable")
	}
	if !strings.Contains(res.Findings[errIdx].Detail, rawKey) {
		t.Fatalf("precondition failed: transport-error Detail no longer embeds the raw key verbatim (Go's url.Error shape may have changed; update this test) — got %s", res.Findings[errIdx].Detail)
	}

	report.RedactPoCs(res.Findings, nil, rawKey, masked)

	if strings.Contains(res.Findings[errIdx].Detail, rawKey) {
		t.Fatalf("error finding Detail still carries the raw key after redaction: %s", res.Findings[errIdx].Detail)
	}
	if !strings.Contains(res.Findings[errIdx].Detail, masked) {
		t.Fatalf("error finding Detail should carry the masked form after redaction, got %s", res.Findings[errIdx].Detail)
	}
}

// Read open but writes denied: delete must be reported as not_tested (we won't
// delete anything we couldn't first create), never as a false positive.
func TestFirestoreWriteDeniedNoDeleteFP(t *testing.T) {
	defer withHost(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		default: // POST/DELETE denied
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED"}}`))
		}
	})()

	res := runFirestore(true)
	for _, f := range res.Findings {
		if f.Check == "delete" && f.Status == report.StatusVulnerable {
			t.Fatal("delete must not be a finding when write was denied (no marker could be planted)")
		}
	}
	// And a not_tested delete note should be present.
	found := false
	for _, f := range res.Findings {
		if f.Check == "delete" && f.Status == report.StatusNotTested {
			found = true
		}
	}
	if !found {
		t.Error("expected a not_tested delete note")
	}
}
