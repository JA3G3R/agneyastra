package report

import (
	"fmt"
	"io"
	"strings"
)

// RenderTable writes a compact, human-readable summary to w. It is intended for
// interactive use; JSON remains the machine-readable contract.
func (r *Report) RenderTable(w io.Writer, verbose bool) error {
	v := r.View(verbose)
	fmt.Fprintf(w, "agneyastra %s — %d key(s) scanned in %dms (active=%v)\n",
		v.Version, v.Scan.KeysScanned, v.Scan.DurationMS, v.Scan.ActiveMode)
	fmt.Fprintf(w, "Findings: %d  |  critical=%d high=%d medium=%d low=%d info=%d  |  blast-radius APIs=%d\n\n",
		v.Summary.Findings,
		v.Summary.BySeverity[string(SevCritical)], v.Summary.BySeverity[string(SevHigh)],
		v.Summary.BySeverity[string(SevMedium)], v.Summary.BySeverity[string(SevLow)],
		v.Summary.BySeverity[string(SevInfo)], v.Summary.BlastRadiusEnabled)

	for _, kr := range v.Results {
		fmt.Fprintf(w, "── %s  [%s, valid=%v]\n", kr.APIKeyMasked, kr.KeyFormat, kr.Valid)
		if len(kr.Projects) > 0 {
			var parts []string
			for _, p := range kr.Projects {
				tag := p.ID
				if p.Numeric {
					tag += "(number)"
				}
				if p.Validated {
					tag += "✓"
				}
				parts = append(parts, tag)
			}
			fmt.Fprintf(w, "   projects: %s\n", strings.Join(parts, ", "))
		}
		if len(kr.Findings) == 0 && len(kr.BlastRadius) == 0 {
			fmt.Fprintf(w, "   no findings\n")
		}
		for _, f := range kr.Findings {
			access := f.Access
			if access == "" {
				access = "-"
			}
			fmt.Fprintf(w, "   [%-8s] %s/%s (%s) %s — %s\n",
				strings.ToUpper(string(f.Severity)), f.Service, f.Check, access, f.Resource, f.Title)
		}
		if len(kr.BlastRadius) > 0 {
			var apis []string
			for _, b := range kr.BlastRadius {
				apis = append(apis, b.API)
			}
			fmt.Fprintf(w, "   blast radius: %s\n", strings.Join(apis, ", "))
		}
		fmt.Fprintln(w)
	}
	return nil
}
