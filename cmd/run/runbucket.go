package run

import (
	"fmt"
	"log"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/bucket"
)

func RunBucketRead(dumpDir string, apiKey string) {
	// Fetch the project config using the API key and the project IDs
	// try to fetch without creds first, then try with each cred type that is available in the credential store

	bucketData := bucket.BucketRead(config.ProjectIds[apiKey])
	fmt.Printf("Bucket data: %v\n", bucketData)
	readreport := map[string]map[string]any{}
	for _, data := range bucketData {

		readreport[data.Bucket] = map[string]any{
			"vulnerable": data.Success,
			"error": data.Error,
			"Contents": data.Data,
			"AuthType": data.AuthType,
		}

	}
	// fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey,"bucket", "read",readreport)
	if dumpDir != "" {
		bucket.DownloadBucketContents(dumpDir, bucketData)
	}

}

func RunBucketWrite(uploadFile string, apiKey string) {

	uploadResults, err := bucket.BucketUpload(config.ProjectIds[apiKey], uploadFile)
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
			"auth_type": result.AuthType,
		}
	}
	// fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey,"bucket", "write",writeReport)

}

func RunBucketDelete(apiKey string) {

	deleteResults := bucket.BucketDelete(config.ProjectIds[apiKey])
	// fmt.Printf("Delete results: %v\n", deleteResults)

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
			"auth_type": result.AuthType,
		}
	}
	// fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey,"bucket", "delete",deleteReport)

}
