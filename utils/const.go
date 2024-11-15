package utils

// Structs for JSON responses
type ProjectConfig struct {
	ProjectID          string   `json:"projectId"`
	AuthorizedDomains  []string `json:"authorizedDomains"`
}

// config file structs

type GeneralConfig struct {
    Debug bool `mapstructure:"debug"`
}

type Config struct {
    General  GeneralConfig                       `mapstructure:"general"`
    Services map[string]map[string]interface{}   `mapstructure:"services"`
}