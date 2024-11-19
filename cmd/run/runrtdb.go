package run

import (
	"fmt"
	"log"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/rtdb"
)

func RunRtdbRead(dumpFile string, apiKey string) {

	// Fetch the project config using the API key and the project IDs
	
	readData := rtdb.ReadFromRTDB(config.RTDBUrls[apiKey], dumpFile)
	readreport := map[string]map[string]any{}
	for _, data := range readData {

		readreport[data.ProjectId] = map[string]any{
			"project_id": data.ProjectId,
			"rtdb_url": data.RTDBUrl,
			"vulnerable": data.Success,
			"error": data.Error,
			"status_code": data.StatusCode,
		}
		
	}
	fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey,"rtdb", "read", readreport)

}

func RunRtdbWrite(data, filepath string, apiKey string) {

	uploadResults, err := rtdb.WriteToRTDB(config.RTDBUrls[apiKey], data , filepath)
	if err != nil {
		log.Printf("Error performing RTDB write check: %v", err)
		return
	}

	writeReport := map[string]map[string]any{}
	for _, result := range uploadResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		writeReport[result.ProjectId] = map[string]any{
			"project_id": result.ProjectId,
			"rtdb_url": result.RTDBUrl,
			"vulnerable": result.Success,
			"error": err,
			"status_code": result.StatusCode,
		}
	}
	fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey,"rtdb", "write",writeReport)

}

func RunRtdbDelete(apiKey string) {

	deleteResults := rtdb.DeleteFromRTDB(config.RTDBUrls[apiKey])
	fmt.Printf("Delete results: %v\n", deleteResults)

	deleteReport := map[string]map[string]any{}
	for _, result := range deleteResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		deleteReport[result.ProjectId] = map[string]any{
			"project_id": result.ProjectId,
			"rtdb_url": result.RTDBUrl,
			"vulnerable": result.Success,
			"error": err,
			"status_code": result.StatusCode,
		}
	}
	fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey,"rtdb", "delete",deleteReport)

}
