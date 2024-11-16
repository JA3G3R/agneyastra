package run

import (
	"log"

	flags "github.com/JA3G3R/agneyastra/flag"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/auth"
)


func RunAnonymousAuth() {
	apiKey := flags.GetAPIKey()
	isVulnerable, sessionInfo, err := auth.AnonymousAuth(apiKey)
	if err != nil {
		log.Fatalf("Error checking anonymous auth: %v", err)
	}
	report.GlobalReport.AddSubService("auth", "anon-auth", report.SubServiceReport{
		Vulnerable: isVulnerable,
		Details: map[string]interface{}{
			"reason": "Anonymous authentication is enabled.",
		},
	})
}	