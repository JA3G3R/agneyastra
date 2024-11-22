package report

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/JA3G3R/agneyastra/services"
)
type ServiceResult struct {
	Vulnerable services.Status
	Error string
	AuthType string
	VulnConfig string
	Remedy string
	Details any
}

type APIKeyReport struct {
	APIKey   string   `json:"api_key"`
	CorrelationScore float64  `json:"correlation_score"`	
	AuthReport map[string]ServiceResult                  `json:"auth"`
	Services map[string]map[string]map[string]ServiceResult      `json:"services"` // Flexible for service-specific formats
	Secrets map[string]map[string][]string      `json:"secrets"` // service -> secret_type -> secrets
}

type Report struct {
	APIKeys []APIKeyReport `json:"api_keys"`
	mu      sync.Mutex
}

var GlobalReport = &Report{
	APIKeys: []APIKeyReport{},
}

func (r *Report) AddCorelationScore(apiKey string, score float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// log.Printf("Adding correlation score: %f for API key: %s\n", score, apiKey)
	var apiKeyReport *APIKeyReport
	for i := range r.APIKeys {
		if r.APIKeys[i].APIKey == apiKey {
			apiKeyReport = &r.APIKeys[i]
			break
		}
	}
	if apiKeyReport == nil {
		newReport := APIKeyReport{
			APIKey:   apiKey,
			Services: make(map[string]map[string]map[string]ServiceResult),
		}
		r.APIKeys = append(r.APIKeys, newReport)
		apiKeyReport = &r.APIKeys[len(r.APIKeys)-1]
	}

	apiKeyReport.CorrelationScore = score

}

func (r *Report) AddSecrets(apiKey string, serviceType string, secrets map[string][]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var apiKeyReport *APIKeyReport
	for i := range r.APIKeys {
		if r.APIKeys[i].APIKey == apiKey {
			apiKeyReport = &r.APIKeys[i]
			break
		}
	}
	if apiKeyReport == nil {
		newReport := APIKeyReport{
			APIKey:   apiKey,
			Services: make(map[string]map[string]map[string]ServiceResult),
		}
		r.APIKeys = append(r.APIKeys, newReport)
		apiKeyReport = &r.APIKeys[len(r.APIKeys)-1]
	}
	if apiKeyReport.Secrets == nil {
		apiKeyReport.Secrets = make(map[string]map[string][]string)
	}
	apiKeyReport.Secrets[serviceType] = secrets
}


// AddServiceReport adds or updates a service-specific report for a given API key.
func (r *Report) AddServiceReport(apiKey, serviceName, subServiceName string,authResult ServiceResult,data map[string]ServiceResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	
	
	var apiKeyReport *APIKeyReport
	for i := range r.APIKeys {
		if r.APIKeys[i].APIKey == apiKey {
			apiKeyReport = &r.APIKeys[i]
			break
		}
	}
	if apiKeyReport == nil {
		newReport := APIKeyReport{
			APIKey:   apiKey,
			Services: make(map[string]map[string]map[string]ServiceResult),
		}
		r.APIKeys = append(r.APIKeys, newReport)
		apiKeyReport = &r.APIKeys[len(r.APIKeys)-1]
	}
	
	if serviceName == "auth" {
		if apiKeyReport.AuthReport == nil {
			apiKeyReport.AuthReport = make(map[string]ServiceResult)
		}
		apiKeyReport.AuthReport[subServiceName] = authResult
	} else {

		if apiKeyReport.Services[serviceName] == nil {
			apiKeyReport.Services[serviceName] = make(map[string]map[string]ServiceResult)
		}
		if apiKeyReport.Services[serviceName][subServiceName] == nil {
			apiKeyReport.Services[serviceName][subServiceName] = make(map[string]ServiceResult)
		}
		for bucket, result := range data {
			apiKeyReport.Services[serviceName][subServiceName][bucket] = result
		}
	}
}

func (r *Report) ReportToJSON() (string, error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert the entire report to JSON with indentation
	jsonData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
	
}