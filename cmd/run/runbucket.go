package run

import (
	"fmt"
	"log"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/bucket"
)

func RunBucketRead(dumpDir string) {
	// Fetch the project config using the API key and the project IDs
	
	bucketData := bucket.BucketRead(config.ProjectIds)
	fmt.Printf("Bucket data: %v\n", bucketData)
	readreport := map[string]map[string]any{}
	for _, data := range bucketData {

		readreport[data.Bucket] = map[string]any{
			"vulnerable": data.Success,
			"error": data.Error,
			"Contents": data.Data,
		}
		
	}
	fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(config.ApiKey,"bucket", "read",readreport)
	if dumpDir != "" {
		bucket.DownloadBucketContents(dumpDir, bucketData)
	}

}

func RunBucketWrite(uploadFile string) {

	uploadResults, err := bucket.BucketUpload(config.ProjectIds, uploadFile)
	fmt.Printf("Upload results: %v\n", uploadResults)
	if err != nil {
		log.Printf("Error uploading file to bucket: %v", err)
		return
	}

	writeReport := map[string]map[string]any{}
	for _, result := range uploadResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		writeReport[result.Bucket] = map[string]any{
			"vulnerable": result.Success,
			"error": err,
			"status_code": result.StatusCode,
		}
	}
	fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(config.ApiKey,"bucket", "write",writeReport)

}

func RunBucketDelete() {

	deleteResults := bucket.BucketDelete(config.ProjectIds)
	fmt.Printf("Delete results: %v\n", deleteResults)

	deleteReport := map[string]map[string]any{}
	for _, result := range deleteResults {
		err := ""
		if result.Error != nil {
			err = result.Error.Error()
		}
		deleteReport[result.Bucket] = map[string]any{
			"vulnerable": result.Success,
			"error": err,
			"status_code": result.StatusCode,
		}
	}
	fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(config.ApiKey,"bucket", "delete",deleteReport)

}
