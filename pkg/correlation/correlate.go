package correlation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"golang.org/x/net/publicsuffix"
)



type PentesterInput struct {
	Emails     []string
	IPRanges   []string
	IPs 	  []string
	Personnel  []string
	Domains    []string
}

// Firebase data structure
type FirebaseData struct {
	Domains []string
	Emails     []string
	IPs        []string
	Personnels []string
}


func extractEmails(data string) []string {
	emailRegex := `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b`
	return extractMatches(emailRegex, data)
}

func checkIPInRange(ipRange string, firebaseIP string) bool {
	// Parse the CIDR range to get the network object
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return false
	}

	// Parse the Firebase IP into an IP object
	ip := net.ParseIP(firebaseIP)
	if ip == nil {
		return false
	}

	// Check if the Firebase IP is within the given IP range
	return ipNet.Contains(ip)
}

// Extract domains
func extractDomains(data string) []string {
	domainRegex := `(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?`
	domains := extractMatches(domainRegex, data)
	var validDomains []string
	for _, domain := range domains {
		if checkForValidTLD(domain) {
			validDomains = append(validDomains, domain)
		}
	}
	return validDomains
}

// Extract IP addresses
func extractIPs(data string) []string {
	ipRegex := `((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`
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
		if checkForValidTLD(domain) {
			domains = append(domains, domain)
		}
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
		// log.Printf("Read data from file: %s\n%s\n", dumpFile,string(data))
		domains := extractDomains(string(data))
		// log.Printf("Extracted domains: %v", domains)
		emails := extractEmails(string(data))
		// log.Printf("Extracted emails: %v", emails)
		ips := extractIPs(string(data))
		// log.Printf("Extracted IPs: %v", ips)
		domainsFromEmail := extractDomainsFromEmails(emails)
		// log.Printf("Extracted domains from emails: %v", domainsFromEmail)
		domains = append(domains, domainsFromEmail...)
		firebaseData[apiKey] = FirebaseData{
			Domains: domains,
			Emails:     emails,
			IPs:        ips,
		}
	}
	return firebaseData
}

func checkForValidTLD(str string) bool {
    etld, im := publicsuffix.PublicSuffix(str)
    var validtld = false
    if im { // ICANN managed
        validtld = true
    } else if strings.IndexByte(etld, '.') >= 0 { // privately managed
        validtld = true
    }
    return validtld
}

func calculateConfidenceScore(input PentesterInput, firebaseData FirebaseData) float64 {
	score := 0.0
	weightTotal := 0.0

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
			if checkIPInRange(ip, firebaseIP) {
				score += ipWeight
			}
		}
		weightTotal += ipWeight
	}

	for _, ip := range input.IPs {
		for _, firebaseIP := range firebaseData.IPs {
			if ip == firebaseIP {
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

	log.Printf("Score: %f, Weight: %f", score, weightTotal)

    // Normalize score with a scaling factor to ensure it's always < 1.0
    const scalingFactor = 1.2 // Adjust this factor as needed to ensure score < 1.0
	if weightTotal > 0 {
        score = score / (weightTotal * scalingFactor)
    }

	return score
}

// func calculateConfidenceScore(input PentesterInput, firebaseData FirebaseData) float64 {
// 	score := 0.0
// 	weightTotal := 0.0

// 	// Email Domain Match (0.6)
// 	emailWeight := 0.6
// 	for _, email := range input.Emails {
// 		for _, firebaseEmail := range firebaseData.Emails {
// 			if strings.Contains(firebaseEmail, email) {
// 				score += emailWeight
// 			}
// 		}
// 		weightTotal += emailWeight
// 	}

// 	// Personnel Match (0.5)
// 	// personnelWeight := 0.5
// 	// for _, person := range input.Personnel {
// 	// 	for _, firebasePerson := range firebaseData.Personnel {
// 	// 		if firebasePerson == person {
// 	// 			score += personnelWeight
// 	// 		}
// 	// 	}
// 	// 	weightTotal += personnelWeight
// 	// }

// 	// IP Match (0.3)
// 	ipWeight := 0.8
// 	for _, ip := range input.IPRanges {
// 		for _, firebaseIP := range firebaseData.IPs {
// 			if checkIPInRange(ip, firebaseIP) {
// 				score += ipWeight
// 			}
// 		}
// 		weightTotal += ipWeight
// 	}

// 	for _, ip := range input.IPs {
// 		for _, firebaseIP := range firebaseData.IPs {
// 			if ip == firebaseIP {
// 				score += ipWeight
// 			}
// 		}
// 		weightTotal += ipWeight
// 	}

// 	// Domain Match (0.4)
// 	domainWeight := 0.4
// 	for _, domain := range input.Domains {
// 		for _, firebaseDomain := range firebaseData.Domains {
// 			if firebaseDomain == domain {
// 				score += domainWeight
// 			}
// 		}
// 		weightTotal += domainWeight
// 	}
// 	log.Printf("Score: %f, Weight: %f", score, weightTotal)
// 	// Normalize score
// 	if weightTotal > 0 {
// 		score = score / weightTotal
// 	}

// 	return score
// }

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
		fmt.Println("Score: ", score)
		report.GlobalReport.AddCorelationScore(apiKey, score*10)
	}
}