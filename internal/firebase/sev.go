package firebase

import "github.com/JA3G3R/agneyastra/internal/report"

// attackerReachable reports whether an auth level is self-serviceable by any
// external attacker with no pre-existing secret. Public, anonymous and
// self-signup all qualify (anyone can obtain them), which makes access unlocked
// at those levels materially more severe than access that needs a custom token
// or real user credentials the attacker must already possess.
func attackerReachable(level string) bool {
	switch level {
	case report.AuthPublic, report.AuthAnon, report.AuthSignup:
		return true
	default:
		return false
	}
}

// authChain returns the escalation chain for a finding: empty for public,
// otherwise the single auth level that unlocked it.
func authChain(level string) []string {
	if level == report.AuthPublic || level == "" {
		return nil
	}
	return []string{level}
}

func readSeverity(level string, hasData bool) report.Severity {
	if !attackerReachable(level) {
		return report.SevLow
	}
	if hasData {
		return report.SevHigh
	}
	return report.SevMedium
}

func writeSeverity(level string) report.Severity {
	if attackerReachable(level) {
		return report.SevHigh
	}
	return report.SevLow
}

func deleteSeverity(level string) report.Severity {
	if attackerReachable(level) {
		return report.SevHigh
	}
	return report.SevLow
}

func errFinding(service, check, resource string, err error) report.Finding {
	return report.Finding{
		Service:  service,
		Check:    check,
		Resource: resource,
		Status:   report.StatusError,
		Severity: report.SevInfo,
		Title:    "Check could not be completed",
		Detail:   err.Error(),
	}
}
