package firebase

import (
	"bytes"
	"context"
	"fmt"

	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

// rtdbRegions are the regional hosts used since Firebase started provisioning
// RTDB instances outside us-central1. us-central1 instances keep the classic
// `*.firebaseio.com` host.
var rtdbRegions = []string{"asia-southeast1", "europe-west1"}

// rtdbHosts returns candidate RTDB base URLs for a project id.
func rtdbHosts(projectID string) []string {
	hosts := []string{
		"https://" + projectID + "-default-rtdb.firebaseio.com",
		"https://" + projectID + ".firebaseio.com",
	}
	for _, r := range rtdbRegions {
		hosts = append(hosts, fmt.Sprintf("https://%s-default-rtdb.%s.firebasedatabase.app", projectID, r))
	}
	return hosts
}

// RTDB checks each candidate Realtime Database host for read (default) and, in
// active mode, write/delete (via create-then-delete of a random child path — we
// never touch existing data and never treat a 404 as a successful delete).
func RTDB(ctx context.Context, client *httpx.Client, apiKey, projectID string, cs *creds.Set, active bool) Result {
	var res Result
	for _, host := range rtdbHosts(projectID) {
		if rtdbHost(ctx, client, host, cs, active, &res) {
			res.Existed = true
			break // one default instance per project; stop at the first that exists
		}
	}
	return res
}

func rtdbHost(ctx context.Context, client *httpx.Client, host string, cs *creds.Set, active bool, res *Result) bool {
	exists := false
	readLevel := ""
	var body []byte
	for _, lvl := range cs.Levels() {
		u := host + "/.json?shallow=true"
		if lvl.Token != "" {
			u += "&access_token=" + lvl.Token
		}
		resp, err := client.Get(ctx, u, nil)
		if err != nil {
			// A non-existent instance often fails DNS/connection — treat as absent.
			return false
		}
		if rtdbAbsent(resp) {
			return false
		}
		exists = true
		if resp.Status == 200 {
			readLevel = lvl.Name
			body = resp.Body
			break
		}
		// 401 permission denied -> escalate.
	}
	if !exists {
		return false
	}

	if readLevel != "" {
		hasData := len(bytes.TrimSpace(body)) > 0 && !bytes.Equal(bytes.TrimSpace(body), []byte("null"))
		// Pull a bounded full copy for the secrets/correlation stage.
		if full := rtdbFullRead(ctx, client, host, cs.Token(readLevel)); len(full) > 0 {
			res.addDump("rtdb:"+host, full)
		}
		res.add(report.Finding{
			Service: "firebase.rtdb", Check: "read", Resource: host, Access: readLevel,
			Status: report.StatusVulnerable, Severity: readSeverity(readLevel, hasData), Confidence: report.ConfConfirmed,
			Title: "Realtime Database is readable by unauthorized users", AuthChain: authChain(readLevel),
			Evidence:    map[string]any{"has_data": hasData},
			Remediation: "Set RTDB rules so `.read` requires proper authorization (never `\".read\": true` or a bare `auth != null`).",
			PoC:         fmt.Sprintf("curl '%s/.json'", host),
		})
	} else {
		res.add(report.Finding{Service: "firebase.rtdb", Check: "read", Resource: host, Status: report.StatusSafe, Severity: report.SevInfo, Title: "RTDB exists but read is denied"})
	}

	if !active {
		res.add(report.Finding{Service: "firebase.rtdb", Check: "write", Resource: host, Status: report.StatusNotTested, Severity: report.SevInfo, Title: "Write not tested (read-only mode; use --active)"})
		return true
	}

	// --- write (active) --- to a random child path, never the root.
	path := marker()
	writeLevel := ""
	for _, lvl := range cs.Levels() {
		u := host + "/" + path + ".json"
		if lvl.Token != "" {
			u += "?access_token=" + lvl.Token
		}
		resp, err := client.Do(ctx, "PUT", u, []byte(`{"agneyastra":"write PoC"}`), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			res.add(errFinding("firebase.rtdb", "write", host, err))
			break
		}
		if resp.Status == 200 {
			writeLevel = lvl.Name
			res.add(report.Finding{
				Service: "firebase.rtdb", Check: "write", Resource: host, Access: lvl.Name,
				Status: report.StatusVulnerable, Severity: writeSeverity(lvl.Name), Confidence: report.ConfConfirmed,
				Title: "Realtime Database accepts unauthorized writes", AuthChain: authChain(lvl.Name),
				Evidence:    map[string]any{"path": path},
				Remediation: "Set RTDB rules so `.write` requires proper authorization.",
				PoC:         fmt.Sprintf("curl -X PUT '%s/%s.json' -d '{\"x\":1}'", host, path),
			})
			break
		}
	}

	// --- delete (active) --- remove the marker we just created.
	if writeLevel != "" {
		deleted := false
		for _, lvl := range cs.Levels() {
			u := host + "/" + path + ".json"
			if lvl.Token != "" {
				u += "?access_token=" + lvl.Token
			}
			resp, err := client.Do(ctx, "DELETE", u, nil, nil)
			if err != nil {
				break
			}
			if resp.Status == 200 {
				deleted = true
				res.add(report.Finding{
					Service: "firebase.rtdb", Check: "delete", Resource: host, Access: lvl.Name,
					Status: report.StatusVulnerable, Severity: deleteSeverity(lvl.Name), Confidence: report.ConfConfirmed,
					Title: "Realtime Database entries can be deleted by unauthorized users", AuthChain: authChain(lvl.Name),
					Evidence:    map[string]any{"path": path, "method": "create-then-delete"},
					Remediation: "Set RTDB rules so `.write` (which governs delete) requires proper authorization.",
					PoC:         fmt.Sprintf("curl -X DELETE '%s/%s.json'", host, path),
				})
				break
			}
		}
		if !deleted {
			res.add(report.Finding{Service: "firebase.rtdb", Check: "delete", Resource: host, Status: report.StatusSafe, Severity: report.SevInfo,
				Title: "Delete denied; note: write PoC path left in database", Evidence: map[string]any{"leftover_path": path}})
		}
	}
	return true
}

func rtdbFullRead(ctx context.Context, client *httpx.Client, host, token string) []byte {
	u := host + "/.json"
	if token != "" {
		u += "?access_token=" + token
	}
	resp, err := client.Get(ctx, u, nil)
	if err != nil || resp.Status != 200 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(resp.Body), []byte("null")) {
		return nil
	}
	return resp.Body
}

// rtdbAbsent reports whether the response means this RTDB instance does not
// exist (as opposed to existing-but-locked at 401).
func rtdbAbsent(resp *httpx.Response) bool {
	if resp.Status == 404 {
		return true
	}
	// A disabled/deprovisioned instance answers 423 Locked or 402.
	if resp.Status == 423 || resp.Status == 402 {
		return true
	}
	if resp.BodyContains("does not exist") || resp.BodyContains("database has been deleted") {
		return true
	}
	return false
}
