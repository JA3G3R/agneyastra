package firebase

import (
	"context"
	"fmt"
	"net/url"

	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

const fbStorageBase = "https://firebasestorage.googleapis.com/v0/b"

// bucketNames returns the candidate default bucket names for a project id. Both
// naming schemes are tried: `.appspot.com` (projects created before Oct 2024)
// and `.firebasestorage.app` (the current default). If the id already looks like
// a fully-qualified bucket it is used verbatim.
func bucketNames(projectID string) []string {
	if hasDot(projectID) {
		return []string{projectID}
	}
	return []string{projectID + ".firebasestorage.app", projectID + ".appspot.com"}
}

func hasDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

type bucketListing struct {
	Prefixes []string `json:"prefixes"`
	Items    []struct {
		Name   string `json:"name"`
		Bucket string `json:"bucket"`
	} `json:"items"`
}

// Storage checks each candidate default bucket for public/authenticated read,
// and — only in active mode — write and delete. Delete is proven by
// create-then-delete of our own marker object; a bare 404 is never treated as a
// successful delete (that was the source of the old delete false positives).
func Storage(ctx context.Context, client *httpx.Client, apiKey, projectID string, cs *creds.Set, active bool) Result {
	var res Result
	for _, bucket := range bucketNames(projectID) {
		exists := storageBucket(ctx, client, apiKey, bucket, cs, active, &res)
		if exists {
			res.Existed = true
			// The default bucket exists under one scheme; no need to probe the
			// other name for the same project.
			break
		}
	}
	return res
}

// storageBucket runs the read/write/delete probes for one bucket and reports
// whether the bucket exists.
func storageBucket(ctx context.Context, client *httpx.Client, apiKey, bucket string, cs *creds.Set, active bool, res *Result) bool {
	listURL := fmt.Sprintf("%s/%s/o?maxResults=15", fbStorageBase, bucket)

	exists := false
	readLevel := ""
	var listing bucketListing
	for _, lvl := range cs.Levels() {
		resp, err := client.Get(ctx, listURL, httpx.BearerHeader(lvl.Token))
		if err != nil {
			res.add(errFinding("firebase.storage", "read", bucket, err))
			return exists // network error: treat as inconclusive, don't guess existence
		}
		if bucketAbsent(resp) {
			return false // definitively no such bucket -> not applicable
		}
		exists = true
		if resp.Status == 200 {
			readLevel = lvl.Name
			_ = resp.JSON(&listing)
			res.addDump("storage:"+bucket, resp.Body)
			break
		}
		// 401/403: exists but locked at this level -> escalate.
	}

	if !exists {
		return false
	}

	if readLevel != "" {
		hasData := len(listing.Items) > 0 || len(listing.Prefixes) > 0
		f := report.Finding{
			Service:     "firebase.storage",
			Check:       "read",
			Resource:    bucket,
			Access:      readLevel,
			Status:      report.StatusVulnerable,
			Severity:    readSeverity(readLevel, hasData),
			Confidence:  report.ConfConfirmed,
			Title:       "Storage bucket contents are listable",
			AuthChain:   authChain(readLevel),
			Evidence:    map[string]any{"item_count": len(listing.Items), "prefix_count": len(listing.Prefixes), "sample": sampleItems(listing)},
			Remediation: "Set Storage rules to require proper authorization, e.g. `allow read: if request.auth != null && <ownership/role check>;` — never `allow read: if true;` or a bare `request.auth != null`.",
			PoC:         fmt.Sprintf("curl '%s'", listURL),
		}
		if !hasData {
			f.Detail = "Listing is permitted but the bucket is currently empty; the rule is still misconfigured."
		}
		res.add(f)
	} else {
		// Exists but no level could read it — record as safe (not shown by default).
		res.add(report.Finding{Service: "firebase.storage", Check: "read", Resource: bucket, Status: report.StatusSafe, Severity: report.SevInfo, Title: "Storage bucket exists but read is denied"})
	}

	if !active {
		// Note that write/delete were not attempted so triage knows coverage.
		res.add(report.Finding{Service: "firebase.storage", Check: "write", Resource: bucket, Status: report.StatusNotTested, Severity: report.SevInfo, Title: "Write not tested (read-only mode; use --active)"})
		return true
	}

	// --- write (active) ---
	object := marker() + ".txt"
	writeLevel := ""
	for _, lvl := range cs.Levels() {
		upURL := fmt.Sprintf("%s/%s/o?name=%s", fbStorageBase, bucket, url.QueryEscape(object))
		h := map[string]string{"Content-Type": "text/plain"}
		for k, v := range httpx.BearerHeader(lvl.Token) {
			h[k] = v
		}
		resp, err := client.Do(ctx, "POST", upURL, []byte("agneyastra storage write PoC"), h)
		if err != nil {
			res.add(errFinding("firebase.storage", "write", bucket, err))
			break
		}
		if resp.Status == 200 {
			writeLevel = lvl.Name
			res.add(report.Finding{
				Service: "firebase.storage", Check: "write", Resource: bucket, Access: lvl.Name,
				Status: report.StatusVulnerable, Severity: writeSeverity(lvl.Name), Confidence: report.ConfConfirmed,
				Title: "Storage bucket accepts unauthorized uploads", AuthChain: authChain(lvl.Name),
				Evidence:    map[string]any{"object": object},
				Remediation: "Restrict writes: `allow write: if request.auth != null && <ownership/role check>;`.",
				PoC:         fmt.Sprintf("curl -X POST '%s' --data-binary @poc.txt", upURL),
			})
			break
		}
	}

	// --- delete (active) ---: only meaningful if we planted a marker.
	if writeLevel != "" {
		delURL := fmt.Sprintf("%s/%s/o/%s", fbStorageBase, bucket, url.QueryEscape(object))
		deleted := false
		for _, lvl := range cs.Levels() {
			resp, err := client.Do(ctx, "DELETE", delURL, nil, httpx.BearerHeader(lvl.Token))
			if err != nil {
				break
			}
			if resp.Status == 200 || resp.Status == 204 {
				deleted = true
				res.add(report.Finding{
					Service: "firebase.storage", Check: "delete", Resource: bucket, Access: lvl.Name,
					Status: report.StatusVulnerable, Severity: deleteSeverity(lvl.Name), Confidence: report.ConfConfirmed,
					Title: "Storage objects can be deleted by unauthorized users", AuthChain: authChain(lvl.Name),
					Evidence:    map[string]any{"object": object, "method": "create-then-delete"},
					Remediation: "Restrict deletes: `allow delete: if request.auth != null && <ownership/role check>;`.",
					PoC:         fmt.Sprintf("curl -X DELETE '%s'", delURL),
				})
				break
			}
		}
		if !deleted {
			// Cleanup could not remove our marker; surface it so the operator can.
			res.add(report.Finding{Service: "firebase.storage", Check: "delete", Resource: bucket, Status: report.StatusSafe, Severity: report.SevInfo,
				Title: "Delete denied; note: write PoC object left in bucket", Evidence: map[string]any{"leftover_object": object}})
		}
	} else {
		res.add(report.Finding{Service: "firebase.storage", Check: "delete", Resource: bucket, Status: report.StatusNotTested, Severity: report.SevInfo,
			Title: "Delete not tested (requires write access to plant a safe marker)"})
	}

	return true
}

// bucketAbsent reports whether the response means the bucket does not exist, as
// opposed to existing-but-protected (403) or existing-and-open (200).
func bucketAbsent(resp *httpx.Response) bool {
	if resp.Status == 404 {
		return true
	}
	if resp.Status == 400 && (resp.BodyContains("does not exist") || resp.BodyContains("invalid bucket") || resp.BodyContains("not a valid")) {
		return true
	}
	return false
}

func sampleItems(l bucketListing) []string {
	var out []string
	for _, it := range l.Items {
		out = append(out, it.Name)
		if len(out) >= 10 {
			break
		}
	}
	return out
}
