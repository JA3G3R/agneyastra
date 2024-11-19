package run

import (
	"fmt"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/firestore"
)

func RunFirestoreRead(apiKey string) {
	// Fetch the project config using the API key and the project IDs
	
	readData := firestore.FirestoreReadDocument(config.ProjectIds[apiKey])
	readreport := map[string]map[string]any{}
	for _, data := range readData {

		readreport[data.ProjectId] = map[string]any{
			"vulnerable": data.Success,
			"error": data.Error.Error(),
		}
		
	}
	fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey,"firestore", "read", readreport)


}

func RunFirestoreWrite(apiKey string) {

	uploadResults:= firestore.FirestoreAddDocument(config.ProjectIds[apiKey])

	writeReport := map[string]map[string]any{}
	for _, result := range uploadResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		writeReport[result.ProjectId] = map[string]any{
			"vulnerable": result.Success,
			"error": err,
		}
	}
	fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey,"firestore", "write",writeReport)

}

func RunFirestoreDelete(apiKey string) {

	deleteResults := firestore.FirestoreDeleteDocument(config.ProjectIds[apiKey])
	fmt.Printf("Delete results: %v\n", deleteResults)

	deleteReport := map[string]map[string]any{}
	for _, result := range deleteResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		deleteReport[result.ProjectId] = map[string]any{
			"vulnerable": result.Success,
			"error": err,
		}
	}
	fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey,"firestore", "delete",deleteReport)

}
