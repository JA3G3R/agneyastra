package report

import (
	"encoding/json"
	"io"
)

// View returns a copy of the report suitable for rendering. When verbose is
// false, only real hits are kept per key — vulnerable findings (this includes
// the info-level "provider enabled" findings, whose Status is vulnerable) — so
// triage sees signal, not the safe/not_applicable/not_tested bookkeeping. The
// summary is left untouched because it was computed over the full data.
func (r *Report) View(verbose bool) *Report {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := &Report{
		Tool:    r.Tool,
		Version: r.Version,
		Scan:    r.Scan,
		Summary: r.Summary,
	}
	for _, kr := range r.Results {
		c := kr // shallow copy; we replace the slices we filter
		if !verbose {
			c.Findings = keepVulnerable(kr.Findings)
		}
		out.Results = append(out.Results, c)
	}
	return out
}

func keepVulnerable(fs []Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.Status == StatusVulnerable {
			out = append(out, f)
		}
	}
	return out
}

// RenderJSON writes the report as indented JSON.
func (r *Report) RenderJSON(w io.Writer, verbose bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r.View(verbose))
}
