package report

import (
	"encoding/json"
	"sync"
)

// Report is the global structure for the JSON report.
type Report struct {
	Services map[string]map[string]SubServiceReport `json:"services"`
	mu       sync.Mutex
}

// SubServiceReport represents the details for each sub-service.
type SubServiceReport struct {
	Vulnerable bool                   `json:"vulnerable"`
	Details    map[string]interface{} `json:"details,omitempty"` // To store other undecided parameters
}

// GlobalReport is the global instance of the report.
var GlobalReport = &Report{
	Services: make(map[string]map[string]SubServiceReport),
}

// AddSubService adds or updates a sub-service report.
func (r *Report) AddSubService(serviceName, subServiceName string, report SubServiceReport) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Services[serviceName] == nil {
		r.Services[serviceName] = make(map[string]SubServiceReport)
	}
	r.Services[serviceName][subServiceName] = report
}

// ToJSON converts the report to JSON format.
func (r *Report) ToJSON() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	jsonData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
