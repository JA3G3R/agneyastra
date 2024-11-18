package report

import (
	"encoding/json"
	"sync"
)

type APIKeyReport struct {
	APIKey   string                          `json:"api_key"`
	Services map[string]map[string]any       `json:"services"` // Flexible for service-specific formats
}

type Report struct {
	APIKeys []APIKeyReport `json:"api_keys"`
	mu      sync.Mutex
}

var GlobalReport = &Report{
	APIKeys: []APIKeyReport{},
}

// AddServiceReport adds or updates a service-specific report for a given API key.
func (r *Report) AddServiceReport(apiKey, serviceName, subServiceName string, data any) {
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
			Services: make(map[string]map[string]any),
		}
		r.APIKeys = append(r.APIKeys, newReport)
		apiKeyReport = &r.APIKeys[len(r.APIKeys)-1]
	}

	if apiKeyReport.Services[serviceName] == nil {
		apiKeyReport.Services[serviceName] = make(map[string]any)
	}
	apiKeyReport.Services[serviceName][subServiceName] = data
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