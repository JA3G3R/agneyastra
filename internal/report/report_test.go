package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	if !(SevCritical.Rank() > SevHigh.Rank() && SevHigh.Rank() > SevMedium.Rank() &&
		SevMedium.Rank() > SevLow.Rank() && SevLow.Rank() > SevInfo.Rank()) {
		t.Fatal("severity ranks are not strictly ordered")
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{Service: "a", Severity: SevLow, Status: StatusVulnerable},
		{Service: "b", Severity: SevCritical, Status: StatusVulnerable},
		{Service: "c", Severity: SevMedium, Status: StatusVulnerable},
	}
	SortFindings(fs)
	if fs[0].Severity != SevCritical || fs[2].Severity != SevLow {
		t.Fatalf("findings not sorted by severity: %+v", fs)
	}
}

func TestFinalizeAndView(t *testing.T) {
	rep := &Report{Tool: "agneyastra", Version: "test"}
	rep.AddResult(KeyResult{
		APIKeyMasked: "AAAA...zzzz",
		Findings: []Finding{
			{Service: "firebase.storage", Check: "read", Severity: SevHigh, Status: StatusVulnerable},
			{Service: "firebase.storage", Check: "write", Severity: SevInfo, Status: StatusNotTested}, // must be ignored
			{Service: "firebase.rtdb", Check: "read", Severity: SevInfo, Status: StatusSafe},          // must be ignored
		},
	})
	rep.AddResult(KeyResult{APIKeyMasked: "BBBB...yyyy", Findings: nil})
	rep.Finalize()

	if rep.Summary.Findings != 1 {
		t.Fatalf("summary.findings = %d, want 1 (safe/not_tested excluded)", rep.Summary.Findings)
	}
	if rep.Summary.BySeverity["high"] != 1 {
		t.Fatalf("summary high = %d, want 1", rep.Summary.BySeverity["high"])
	}
	if rep.Summary.VulnerableKeys != 1 {
		t.Fatalf("vulnerable keys = %d, want 1", rep.Summary.VulnerableKeys)
	}
	// The vulnerable key must sort first.
	if rep.Results[0].APIKeyMasked != "AAAA...zzzz" {
		t.Fatalf("vulnerable key not sorted first: %s", rep.Results[0].APIKeyMasked)
	}

	// Non-verbose view drops non-vulnerable findings.
	view := rep.View(false)
	if len(view.Results[0].Findings) != 1 {
		t.Fatalf("view findings = %d, want 1", len(view.Results[0].Findings))
	}

	// Verbose keeps them all.
	if len(rep.View(true).Results[0].Findings) != 3 {
		t.Fatal("verbose view should keep all findings")
	}
}

func TestRenderJSONValid(t *testing.T) {
	rep := &Report{Tool: "agneyastra", Version: "test"}
	rep.AddResult(KeyResult{APIKeyMasked: "x", Findings: []Finding{{Service: "s", Check: "read", Severity: SevHigh, Status: StatusVulnerable}}})
	rep.Finalize()
	var buf bytes.Buffer
	if err := rep.RenderJSON(&buf, false); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if back["tool"] != "agneyastra" {
		t.Fatal("missing tool field / broken struct tags")
	}
}
