// Package firebase implements the per-service access checks (auth, storage,
// realtime database, firestore). Every check is *existence-aware*: it first
// establishes whether the resource actually exists for the project before
// deciding whether denied/absent responses mean "safe" or "not applicable".
// Reads and listings run by default; anything that mutates the target (write,
// delete, sending sign-in emails) runs only when active is true.
package firebase

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/JA3G3R/agneyastra/internal/report"
)

// Result is what each service check returns to the scanner.
type Result struct {
	Findings []report.Finding
	// Existed is true if at least one real resource for the project was
	// confirmed to exist (used to mark the project validated).
	Existed bool
	// Dumps maps a resource identifier to raw response bytes, for the optional
	// secrets/correlation post-processing stages.
	Dumps map[string][]byte
}

func (r *Result) add(f report.Finding) { r.Findings = append(r.Findings, f) }
func (r *Result) addDump(k string, v []byte) {
	if len(v) == 0 {
		return
	}
	if r.Dumps == nil {
		r.Dumps = map[string][]byte{}
	}
	r.Dumps[k] = v
}

// marker returns a random, clearly-attributable token for probe object/doc/key
// names so anything we create is obviously ours and easy to clean up.
func marker() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "agneyastra-poc-" + hex.EncodeToString(b)
}

// randHex returns n random hex chars.
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
