package run

import (
	"log"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/services/bucket"
)

func RunBucketRead(dumpDir string, apiKey string) {
	// Fetch the project config using the API key and the project IDs
	// try to fetch without creds first, then try with each cred type that is available in the credential store

	bucketData := bucket.BucketRead(config.ProjectIds[apiKey])
	// log.Printf("Bucket data: %v\n", bucketData)
	readreport := map[string][]report.ServiceResult{}
	for _, data := range bucketData {
		var remedy string
		var vulnconf string
		if data.Success == services.StatusVulnerable {
			auth_type := data.AuthType
			if data.AuthType == "" {
				auth_type = "public"
			}
			remedy = services.Remedies["bucket"]["read"][auth_type]
			vulnconf = services.VulnConfigs["bucket"]["read"][auth_type]
			readreport[data.Bucket] = append(readreport[data.Bucket], report.ServiceResult{
				Vulnerable: data.Success,
				Error:      data.Error.Error(),
				Details:    map[string]bucket.KeysResponseRecursive{"Contents": data.Data},
				AuthType:   auth_type,
				Remedy:     remedy,
				VulnConfig: vulnconf,
			})
		}

	}
	// fmt.Printf("Writing to report: %v\n", readreport)

	report.GlobalReport.AddServiceReport(apiKey, "bucket", "read", report.ServiceResult{}, readreport)
	if dumpDir != "" {
		bucket.DownloadBucketContents(dumpDir, bucketData)
	}

}

func RunBucketWrite(uploadFile string, apiKey string) {

	uploadResults, err := bucket.BucketUpload(config.ProjectIds[apiKey], uploadFile)
	// fmt.Printf("Upload results: %v\n", uploadResults)
	if err != nil {
		log.Printf("Error uploading file to bucket: %v", err)
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
			writeReport[result.Bucket] = append(writeReport[result.Bucket], report.ServiceResult{
				Vulnerable: result.Success,
				Error:      err,
				Details:    map[string]string{"status_code": result.StatusCode},
				AuthType:   auth_type,
				Remedy:     remedy,
				VulnConfig: vulnconf,
			})
		}
	}
	// fmt.Printf("Writing to report: %v\n", writeReport)
	report.GlobalReport.AddServiceReport(apiKey, "bucket", "write", report.ServiceResult{}, writeReport)

}

func RunBucketDelete(apiKey string) {

	deleteResults := bucket.BucketDelete(config.ProjectIds[apiKey])
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
			deleteReport[result.Bucket] = append(deleteReport[result.Bucket], report.ServiceResult{
				Vulnerable: result.Success,
				Error:      err,
				Details:    map[string]string{"status_code": result.StatusCode},
				AuthType:   auth_type,
				Remedy:     remedy,
				VulnConfig: vulnconf,
			})
		}
	}
	// fmt.Printf("Writing to report: %v\n", deleteReport)

	report.GlobalReport.AddServiceReport(apiKey, "bucket", "delete", report.ServiceResult{}, deleteReport)

}
