package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)


func GetProjectConfig(apiKey string) (*ProjectConfig, error) {
	
	url := fmt.Sprintf("https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=%s", apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch project config, status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var projectConfig ProjectConfig
	err = json.Unmarshal(body, &projectConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	return &projectConfig, nil
}


func ExtractDomainsForStorage(config ProjectConfig) []string {
	domainSet := make(map[string]struct{}) // Use a map to track unique domains
	var domains []string

	// Add the projectId as the first element (unique by default)
	domainSet[config.ProjectID] = struct{}{}
	domains = append(domains, config.ProjectID)

	// Iterate over the authorized domains
	for _, domain := range config.AuthorizedDomains {
		// Check if the domain ends with "firebaseapp.com" or "web.app"
		if strings.HasSuffix(domain, ".firebaseapp.com") || strings.HasSuffix(domain, ".web.app") {
			// Extract the subdomain part (before ".firebaseapp.com" or ".web.app")
			parts := strings.Split(domain, ".")
			if len(parts) > 0 {
				subdomain := parts[0]
				// Add to the map if it is not already present
				if _, exists := domainSet[subdomain]; !exists {
					domainSet[subdomain] = struct{}{}
					domains = append(domains, subdomain)
				}
			}
		}
	}

	return domains
}


func LoadConfig(path string) (Config, error) {
    var config Config

    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(path)

    if err := viper.ReadInConfig(); err != nil {
        return config, fmt.Errorf("error reading config file: %w", err)
    }

    if err := viper.Unmarshal(&config); err != nil {
        return config, fmt.Errorf("error unmarshaling config: %w", err)
    }

    return config, nil
}

func RandomString(length int) string {

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}