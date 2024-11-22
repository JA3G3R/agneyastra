package secrets

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"gopkg.in/yaml.v3"
)

type SecretsRegexes map[string]string

func extractSecrets(secretsRegexes SecretsRegexes, data string) map[string][]string {
	secrets := make(map[string][]string)

	for secretType, secretRegex := range secretsRegexes {
		re := regexp.MustCompile(secretRegex)
		matches := re.FindAllString(data, -1)
		if len(matches) > 0 {
			secrets[secretType] = matches
		}
	}

	return secrets
}

func ExtractSecrets() {
	var secretsRegexes SecretsRegexes
	// fmt.Println("Secrets file: ", config.SecretsRegexFile)
	if config.SecretsRegexFile == "" {
		// download and load a json file containing secret_type : secret_regex from the url : https://devanghacks.in/varunastra/regexes.json
		// store the file in /tmp/regexes.json
		// use the file to extract secrets
		url := "https://devanghacks.in/varunastra/regexes.json"
		resp, err := http.Get(url)
		if err != nil {
			log.Fatalf("Error downloading regexes.json: %v", err)
			return
		}
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&secretsRegexes)
		if err != nil {
			log.Fatalf("Error decoding regexes.json: %v", err)
			return
		}
		// fmt.Println("Secrets regexes: ", secretsRegexes)
	} else {
		// read the file and load the regexes
		// use the file to extract secrets
		//check if file ends with .yml or .yaml
		data, err := ioutil.ReadFile(config.SecretsRegexFile)
		if config.SecretsRegexFile[len(config.SecretsRegexFile)-4:] == ".yml" || config.SecretsRegexFile[len(config.SecretsRegexFile)-5:] == ".yaml" {
			err = yaml.Unmarshal([]byte(data), &secretsRegexes)
		}
		if err != nil {
			log.Fatalf("Error reading regex file: %v", err)
			return
		}
		err = json.Unmarshal(data, &secretsRegexes)
		if err != nil {
			log.Fatalf("Error unmarshalling regex file: %v", err)
			return
		}
	}
	for _, apiKey := range config.ApiKeys {
		// rtdb
		// read the dump file from dump/rtdb/<apikey>
		dumpFile := fmt.Sprintf("dump/rtdb/%s", apiKey)
		data, err := ioutil.ReadFile(dumpFile)
		if err != nil {
			log.Printf("Error reading RTDB dump file for correlation: %v", err)
			continue
		}
		// extract secrets
		secrets := extractSecrets(secretsRegexes, string(data))
		// store the secrets in the report
		report.GlobalReport.AddSecrets(apiKey, "rtdb", secrets)

	}

}