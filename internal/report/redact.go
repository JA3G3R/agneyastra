package report

import "strings"

// RedactPoCs replaces every literal occurrence of rawKey in fs' and brs' PoC
// and Detail fields with masked, in place.
//
// Why this exists (todos/agneyastra.md, 2026-08-18): PoC strings are built
// deep inside the google/firebase packages from the literal HTTP request that
// was actually sent — which, for several checks (the Google blast-radius
// sweep in internal/google, Firestore's read PoC in internal/firebase),
// necessarily contains the live API key as a query parameter. api_key /
// api_key_masked have always respected --show-key; poc did not, regardless of
// which package built the string. The only reliable fix is a single
// post-processing pass applied to every finding, independent of which package
// produced the PoC or whether a future one repeats the same pattern — see
// internal/scanner.redactKeyResult for the (single) call site, gated on
// !cfg.ShowKey.
//
// It is a no-op if rawKey is empty (a strings.ReplaceAll with an empty old
// string would otherwise insert masked between every rune of every string —
// corrupting output rather than protecting it) or if rawKey already equals
// masked.
func RedactPoCs(fs []Finding, brs []BlastRadiusEntry, rawKey, masked string) {
	if rawKey == "" || rawKey == masked {
		return
	}
	for i := range fs {
		fs[i].PoC = strings.ReplaceAll(fs[i].PoC, rawKey, masked)
		fs[i].Detail = strings.ReplaceAll(fs[i].Detail, rawKey, masked)
	}
	for i := range brs {
		brs[i].PoC = strings.ReplaceAll(brs[i].PoC, rawKey, masked)
		brs[i].Detail = strings.ReplaceAll(brs[i].Detail, rawKey, masked)
	}
}
