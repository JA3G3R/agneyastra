package run

import (
	"log"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/services/rtdb"
)

func RunRtdbRead(dump bool, apiKey string) {

	log.Printf("RunRtdbRead called with dump: %v, apiKey: %v\n", dump, apiKey)
	// Fetch the project config using the API key and the project IDs

	readData := rtdb.ReadFromRTDB(config.RTDBUrls[apiKey], dump, apiKey)
	// log.Printf("RTDB data: %v\n", readData)
	readreport := map[string][]report.ServiceResult{}
	for _, data := range readData {
		log.Printf("vulnerable: %v, error: %v, authType: %v, statusCode: %v, rtdbUrl: %v\n", data.Success, data.Error, data.AuthType, data.StatusCode, data.RTDBUrl)
		var remedy string
		var vulnconf string
		if data.Success == services.StatusVulnerable {
			auth_type := data.AuthType
			if data.AuthType == "" {
				auth_type = "public"
			}
			remedy = services.Remedies["bucket"]["read"][auth_type]
			vulnconf = services.VulnConfigs["bucket"]["read"][auth_type]
			readreport[data.ProjectId] = append(readreport[data.ProjectId], report.ServiceResult{
				Vulnerable: data.Success,
				Error:      data.Error.Error(),
				AuthType:   data.AuthType,
				Remedy:     remedy,
				VulnConfig: vulnconf,
				Details: map[string]string{
					"status_code": data.StatusCode,
					"rtdb_url":    data.RTDBUrl,
				},
			})
		}

	}
	// fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey, "rtdb", "read", report.ServiceResult{}, readreport)

}

func RunRtdbWrite(data, filepath string, apiKey string) {

	uploadResults, err := rtdb.WriteToRTDB(config.RTDBUrls[apiKey], data, filepath)
	if err != nil {
		log.Printf("Error performing RTDB write check: %v", err)
		return
	}

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
			writeReport[result.ProjectId] = append(writeReport[result.ProjectId], report.ServiceResult{
				Details: map[string]string{
					"rtdb_url":    result.RTDBUrl,
					"status_code": result.StatusCode,
				},
				Vulnerable: result.Success,
				Error:      err,
				AuthType:   result.AuthType,
				Remedy:     remedy,
				VulnConfig: vulnconf,
			})
		}
	}
	// fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey, "rtdb", "write", report.ServiceResult{}, writeReport)

}

func RunRtdbDelete(apiKey string) {

	deleteResults := rtdb.DeleteFromRTDB(config.RTDBUrls[apiKey])
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
			deleteReport[result.ProjectId] = append(deleteReport[result.ProjectId], report.ServiceResult{
				Details: map[string]string{
					"rtdb_url":    result.RTDBUrl,
					"status_code": result.StatusCode,
				},
				Vulnerable: result.Success,
				Error:      err,
				AuthType:   result.AuthType,
				Remedy:     remedy,
				VulnConfig: vulnconf,
			})
		}
	}
	// fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey, "rtdb", "delete", report.ServiceResult{}, deleteReport)

}
