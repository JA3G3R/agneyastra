package run

import (
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/services/firestore"
)

func RunFirestoreRead(apiKey string) {
	// Fetch the project config using the API key and the project IDs
	
	readData := firestore.FirestoreReadDocument(config.ProjectIds[apiKey])
	readreport := map[string][]report.ServiceResult{}
	for _, data := range readData {
		var remedy string
		var vulnconf string
		if data.Success == services.StatusVulnerable {
			auth_type := data.AuthType
			if data.AuthType == "" {
				auth_type = "public"
			}
			remedy = services.Remedies["bucket"]["read"][auth_type]
			vulnconf = services.VulnConfigs["bucket"]["read"][auth_type]
			readreport[data.ProjectId] = append(readreport[data.ProjectId],report.ServiceResult{
				Vulnerable: data.Success,
				Error: data.Error.Error(),
				AuthType: data.AuthType,
				Remedy: remedy,
				VulnConfig: vulnconf,
			})
		} 
		
	}
	// fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey,"firestore", "read",report.ServiceResult{},  readreport)


}

func RunFirestoreWrite(apiKey string) {

	uploadResults:= firestore.FirestoreAddDocument(config.ProjectIds[apiKey])

	writeReport := map[string][]report.ServiceResult{}
	for _, result := range uploadResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		var remedy string
		var vulnconf string
		if result.Success == services.StatusVulnerable {
			auth_type := result.AuthType
			if result.AuthType == "" {
				auth_type = "public"
			}
			remedy = services.Remedies["bucket"]["write"][auth_type]
			vulnconf = services.VulnConfigs["bucket"]["write"][auth_type]
			writeReport[result.ProjectId] = append(writeReport[result.ProjectId],report.ServiceResult{
				Vulnerable: result.Success,
				Error: err,
				AuthType: result.AuthType,
				Remedy: remedy,
				VulnConfig: vulnconf,
			})
		} 
	}
	// fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey,"firestore", "write",report.ServiceResult{},writeReport)

}

func RunFirestoreDelete(apiKey string) {

	deleteResults := firestore.FirestoreDeleteDocument(config.ProjectIds[apiKey])
	// fmt.Printf("Delete results: %v\n", deleteResults)

	deleteReport := map[string][]report.ServiceResult{}
	for _, result := range deleteResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		var remedy string
		var vulnconf string
		if result.Success == services.StatusVulnerable {
			auth_type := result.AuthType
			if result.AuthType == "" {
				auth_type = "public"
			}
			remedy = services.Remedies["bucket"]["delete"][auth_type]
			vulnconf = services.VulnConfigs["bucket"]["delete"][auth_type]
			deleteReport[result.ProjectId] = append(deleteReport[result.ProjectId],report.ServiceResult{
				Vulnerable: result.Success,
				Error: err,
				AuthType: result.AuthType,
				Remedy: remedy,
				VulnConfig: vulnconf,
			})
		} 
	}
	// fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey,"firestore", "delete",report.ServiceResult{},deleteReport)

}
