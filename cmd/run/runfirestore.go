package run

import (
	"fmt"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/firestore"
)

func RunFirestoreRead() {
	// Fetch the project config using the API key and the project IDs
	
	readData := firestore.FirestoreReadDocument(config.ProjectIds)
	readreport := map[string]map[string]any{}
	for _, data := range readData {

		readreport[data.ProjectId] = map[string]any{
			"vulnerable": data.Success,
			"error": data.Error.Error(),
		}
		
	}
	fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(config.ApiKey,"firestore", "read", readreport)


}

func RunFirestoreWrite() {

	uploadResults:= firestore.FirestoreAddDocument(config.ProjectIds)

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
	report.GlobalReport.AddServiceReport(config.ApiKey,"firestore", "write",writeReport)

}

func RunFirestoreDelete() {

	deleteResults := firestore.FirestoreDeleteDocument(config.ProjectIds)
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

	report.GlobalReport.AddServiceReport(config.ApiKey,"firestore", "delete",deleteReport)

}
