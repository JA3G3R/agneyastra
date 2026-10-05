package firebase

import (
	"context"
	"fmt"

	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

// firestoreHost is the API host; it is a var so tests can point checks at an
// httptest server without any live calls.
var firestoreHost = "https://firestore.googleapis.com"

// firestoreBase builds the REST documents root for the default database. The v1
// REST API enforces Firestore security rules for API-key/ID-token requests, so
// it is a faithful (and far simpler) replacement for the old gRPC-channel
// scraper — a 200 means the rules genuinely allowed the operation.
func firestoreBase(projectID string) string {
	return fmt.Sprintf("%s/v1/projects/%s/databases/(default)/documents", firestoreHost, projectID)
}

// commonCollections are sampled for evidence once read is known to be allowed.
var commonCollections = []string{"users", "posts", "messages", "chats", "config", "settings", "orders", "products"}

// Firestore checks the default Cloud Firestore database for read (default) and,
// in active mode, write/delete (create-then-delete of a document in a random
// collection, so no existing data is touched).
func Firestore(ctx context.Context, client *httpx.Client, apiKey, projectID string, cs *creds.Set, active bool) Result {
	var res Result
	base := firestoreBase(projectID)
	probe := "agneyastra_" + randHex(8)

	// --- read / existence ---
	exists := false
	readLevel := ""
	for _, lvl := range cs.Levels() {
		u := fmt.Sprintf("%s/%s?pageSize=1&key=%s", base, probe, apiKey)
		resp, err := client.Get(ctx, u, httpx.BearerHeader(lvl.Token))
		if err != nil {
			res.add(errFinding("firebase.firestore", "read", projectID, err))
			return res
		}
		absent, disabled, denied, ok := classifyFirestore(resp)
		if absent || disabled {
			return res // database not present or Firestore API not enabled -> not applicable
		}
		exists = true
		if ok {
			readLevel = lvl.Name
			break
		}
		if denied {
			continue // exists but locked -> escalate
		}
	}
	if !exists {
		return res
	}
	res.Existed = true

	if readLevel != "" {
		sample := sampleFirestore(ctx, client, apiKey, base, cs.Token(readLevel))
		res.add(report.Finding{
			Service: "firebase.firestore", Check: "read", Resource: projectID, Access: readLevel,
			Status: report.StatusVulnerable, Severity: readSeverity(readLevel, len(sample) > 0), Confidence: report.ConfConfirmed,
			Title: "Cloud Firestore is readable by unauthorized users", AuthChain: authChain(readLevel),
			Evidence:    map[string]any{"readable_collections": sample},
			Remediation: "Tighten Firestore rules so reads require proper authorization (never `allow read: if true;` or a bare `request.auth != null`).",
			PoC:         fmt.Sprintf("curl '%s/%s?key=%s'", base, commonCollections[0], apiKey),
		})
	} else {
		res.add(report.Finding{Service: "firebase.firestore", Check: "read", Resource: projectID, Status: report.StatusSafe, Severity: report.SevInfo, Title: "Firestore exists but read is denied"})
	}

	if !active {
		res.add(report.Finding{Service: "firebase.firestore", Check: "write", Resource: projectID, Status: report.StatusNotTested, Severity: report.SevInfo, Title: "Write not tested (read-only mode; use --active)"})
		return res
	}

	// --- write (active) --- create a document in the random probe collection.
	docID := marker()
	writeLevel := ""
	for _, lvl := range cs.Levels() {
		u := fmt.Sprintf("%s/%s?documentId=%s&key=%s", base, probe, docID, apiKey)
		resp, err := client.PostJSON(ctx, u, map[string]any{
			"fields": map[string]any{"agneyastra": map[string]any{"stringValue": "write PoC"}},
		}, httpx.BearerHeader(lvl.Token))
		if err != nil {
			res.add(errFinding("firebase.firestore", "write", projectID, err))
			break
		}
		if resp.Status == 200 {
			writeLevel = lvl.Name
			res.add(report.Finding{
				Service: "firebase.firestore", Check: "write", Resource: projectID, Access: lvl.Name,
				Status: report.StatusVulnerable, Severity: writeSeverity(lvl.Name), Confidence: report.ConfConfirmed,
				Title: "Cloud Firestore accepts unauthorized writes", AuthChain: authChain(lvl.Name),
				Evidence:    map[string]any{"collection": probe, "document": docID},
				Remediation: "Tighten Firestore rules so writes require proper authorization.",
			})
			break
		}
	}

	// --- delete (active) --- remove the document we created.
	if writeLevel != "" {
		deleted := false
		for _, lvl := range cs.Levels() {
			u := fmt.Sprintf("%s/%s/%s?key=%s", base, probe, docID, apiKey)
			resp, err := client.Do(ctx, "DELETE", u, nil, httpx.BearerHeader(lvl.Token))
			if err != nil {
				break
			}
			if resp.Status == 200 {
				deleted = true
				res.add(report.Finding{
					Service: "firebase.firestore", Check: "delete", Resource: projectID, Access: lvl.Name,
					Status: report.StatusVulnerable, Severity: deleteSeverity(lvl.Name), Confidence: report.ConfConfirmed,
					Title: "Cloud Firestore documents can be deleted by unauthorized users", AuthChain: authChain(lvl.Name),
					Evidence:    map[string]any{"collection": probe, "document": docID, "method": "create-then-delete"},
					Remediation: "Tighten Firestore rules so deletes require proper authorization.",
				})
				break
			}
		}
		if !deleted {
			res.add(report.Finding{Service: "firebase.firestore", Check: "delete", Resource: projectID, Status: report.StatusSafe, Severity: report.SevInfo,
				Title: "Delete denied; note: write PoC document left in Firestore", Evidence: map[string]any{"leftover": probe + "/" + docID}})
		}
	} else {
		res.add(report.Finding{Service: "firebase.firestore", Check: "delete", Resource: projectID, Status: report.StatusNotTested, Severity: report.SevInfo,
			Title: "Delete not tested (requires write access to plant a safe marker)"})
	}

	return res
}

// classifyFirestore maps a documents-list response to the four states we care
// about. The order of checks matters: SERVICE_DISABLED and NOT_FOUND both arrive
// as non-200 and must not be confused with a rules-based PERMISSION_DENIED.
func classifyFirestore(resp *httpx.Response) (absent, disabled, denied, ok bool) {
	switch resp.Status {
	case 200:
		return false, false, false, true
	case 404:
		return true, false, false, false
	case 400:
		// Datastore-mode projects can't be read via the Firestore documents API.
		if resp.BodyContains("datastore mode") {
			return true, false, false, false
		}
		return true, false, false, false
	case 403:
		if resp.BodyContains("SERVICE_DISABLED") || resp.BodyContains("has not been used in project") || resp.BodyContains("it is disabled") {
			return false, true, false, false
		}
		return false, false, true, false
	default:
		// Treat other errors as "exists but couldn't read" (escalate/deny).
		return false, false, true, false
	}
}

// sampleFirestore returns the names of common collections that are readable and
// currently hold at least one document, as concrete evidence of exposure.
func sampleFirestore(ctx context.Context, client *httpx.Client, apiKey, base, token string) []string {
	var found []string
	for _, col := range commonCollections {
		u := fmt.Sprintf("%s/%s?pageSize=1&key=%s", base, col, apiKey)
		resp, err := client.Get(ctx, u, httpx.BearerHeader(token))
		if err != nil || resp.Status != 200 {
			continue
		}
		if resp.BodyContains("\"documents\"") {
			found = append(found, col)
		}
	}
	return found
}
