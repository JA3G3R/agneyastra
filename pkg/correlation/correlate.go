package correlation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
)



type PentesterInput struct {
	Subdomains []string
	Emails     []string
	IPRanges   []string
	Personnel  []string
	Domains    []string
}

// Firebase data structure
type FirebaseData struct {
	Subdomains []string
	Emails     []string
	IPs        []string
	Domains    []string
	Personnels []string
}


func extractEmails(data string) []string {
	emailRegex := `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b`
	return extractMatches(emailRegex, data)
}

// Extract domains
func extractDomains(data string) []string {
	domainRegex := `^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`
	return extractMatches(domainRegex, data)
}

// Extract IP addresses
func extractIPs(data string) []string {
	ipRegex := `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`
	return extractMatches(ipRegex, data)
}

// Generic function to extract matches using a regex
func extractMatches(pattern string, data string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(data, -1)
	return matches
}

func extractDomainsFromEmails(emails []string) []string {
	domainSet := make(map[string]struct{})
	for _, email := range emails {
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domainSet[parts[1]] = struct{}{}
		}
	}

	// Convert the set to a slice
	var domains []string
	for domain := range domainSet {
		domains = append(domains, domain)
	}

	return domains
}

func getRTDBData() map[string]FirebaseData {

	firebaseData := make(map[string]FirebaseData)
	for _, apiKey := range config.ApiKeys {
		// read the dump file from dump/rtdb/<apikey>
		dumpFile := fmt.Sprintf("dump/rtdb/%s", apiKey)
		data, err := ioutil.ReadFile(dumpFile)
		if err != nil {
			log.Printf("Error reading RTDB dump file for correlation: %v", err)
			continue
		}
		domains := extractDomains(string(data))
		emails := extractEmails(string(data))
		ips := extractIPs(string(data))
		domains = append(domains, extractDomainsFromEmails(emails)...)
		firebaseData[apiKey] = FirebaseData{
			Subdomains: domains,
			Emails:     emails,
			IPs:        ips,
		}
	}
	return firebaseData
}

func calculateConfidenceScore(input PentesterInput, firebaseData FirebaseData) float64 {
	score := 0.0
	weightTotal := 0.0

	// Subdomain Match (0.7 for exact match, 0.5 for partial match)
	subdomainWeight := 0.5
	partialSubdomainWeight := 0.5
	for _, subdomain := range input.Subdomains {
		for _, firebaseSubdomain := range firebaseData.Subdomains {
			if firebaseSubdomain == subdomain {
				score += subdomainWeight
			} else if strings.Contains(firebaseSubdomain, subdomain) || strings.Contains(subdomain, firebaseSubdomain) {
				score += partialSubdomainWeight
			}
		}
		weightTotal += subdomainWeight
	}

	// Email Domain Match (0.6)
	emailWeight := 0.6
	for _, email := range input.Emails {
		for _, firebaseEmail := range firebaseData.Emails {
			if strings.Contains(firebaseEmail, email) {
				score += emailWeight
			}
		}
		weightTotal += emailWeight
	}

	// Personnel Match (0.5)
	// personnelWeight := 0.5
	// for _, person := range input.Personnel {
	// 	for _, firebasePerson := range firebaseData.Personnel {
	// 		if firebasePerson == person {
	// 			score += personnelWeight
	// 		}
	// 	}
	// 	weightTotal += personnelWeight
	// }

	// IP Match (0.3)
	ipWeight := 0.8
	for _, ip := range input.IPRanges {
		for _, firebaseIP := range firebaseData.IPs {
			if strings.Contains(firebaseIP, ip) {
				score += ipWeight
			}
		}
		weightTotal += ipWeight
	}

	// Domain Match (0.4)
	domainWeight := 0.4
	for _, domain := range input.Domains {
		for _, firebaseDomain := range firebaseData.Domains {
			if firebaseDomain == domain {
				score += domainWeight
			}
		}
		weightTotal += domainWeight
	}

	// Normalize score
	if weightTotal > 0 {
		score = score / weightTotal
	}

	return score
}

func AddCorelationScore() {
	// open the pentester input file
	// unmashal the json data
	if config.PentestDataFilePath == "" {
		log.Println("Could not find pentest data file. Skipping correlation.")
		return
	}
	fileData, err := ioutil.ReadFile(config.PentestDataFilePath)
	if err != nil {
		log.Fatalf("Error reading pentester input file: %v", err)
		return
	}
	var input PentesterInput
	err = json.Unmarshal(fileData, &input)
	if err != nil {
		log.Fatalf("Error unmarshaling pentester input data: %v", err)
		return
	}

	firebaseData := getRTDBData()
	for apiKey, data := range firebaseData {
		score := calculateConfidenceScore(input, data)
		report.GlobalReport.AddCorelationScore(apiKey, score)
	}
}