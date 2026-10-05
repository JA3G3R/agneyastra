// Package correlation scores how strongly the data recovered from a Firebase
// instance ties back to the operator's target (supplied as a "pentest data"
// file of emails/domains/IPs). It replaces the old package that read dump files
// off disk and mutated a global report; these are pure functions that operate on
// in-memory data.
package correlation

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Input is the operator-supplied target profile.
type Input struct {
	Emails   []string `json:"Emails"`
	IPRanges []string `json:"IPRanges"`
	IPs      []string `json:"IPs"`
	Domains  []string `json:"Domains"`
}

// Load reads a pentest-data JSON file.
func Load(path string) (*Input, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

var (
	emailRE  = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b`)
	ipRE     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	domainRE = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
)

// Score returns a 0..10 confidence that the recovered data belongs to the
// target described by input. blobs are the raw bodies read from the instance.
func Score(input *Input, blobs [][]byte) float64 {
	if input == nil || len(blobs) == 0 {
		return 0
	}
	var sb strings.Builder
	for _, b := range blobs {
		sb.Write(b)
		sb.WriteByte('\n')
	}
	data := sb.String()

	foundEmails := dedupe(emailRE.FindAllString(data, -1))
	foundIPs := dedupe(ipRE.FindAllString(data, -1))
	foundDomains := validDomains(domainRE.FindAllString(data, -1))
	for _, e := range foundEmails {
		if at := strings.LastIndex(e, "@"); at >= 0 {
			foundDomains = append(foundDomains, e[at+1:])
		}
	}

	score, weight := 0.0, 0.0
	const wEmail, wIP, wDomain = 0.6, 0.8, 0.4

	for _, e := range input.Emails {
		weight += wEmail
		for _, fe := range foundEmails {
			if strings.EqualFold(fe, e) || strings.Contains(strings.ToLower(fe), strings.ToLower(e)) {
				score += wEmail
				break
			}
		}
	}
	for _, r := range input.IPRanges {
		weight += wIP
		if _, ipNet, err := net.ParseCIDR(r); err == nil {
			for _, fip := range foundIPs {
				if ip := net.ParseIP(fip); ip != nil && ipNet.Contains(ip) {
					score += wIP
					break
				}
			}
		}
	}
	for _, want := range input.IPs {
		weight += wIP
		for _, fip := range foundIPs {
			if fip == want {
				score += wIP
				break
			}
		}
	}
	for _, d := range input.Domains {
		weight += wDomain
		for _, fd := range foundDomains {
			if strings.EqualFold(fd, d) {
				score += wDomain
				break
			}
		}
	}

	if weight == 0 {
		return 0
	}
	// Normalise to <1 then scale to a 0..10 confidence.
	const scaling = 1.2
	return (score / (weight * scaling)) * 10
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func validDomains(in []string) []string {
	var out []string
	for _, d := range dedupe(in) {
		if etld, icann := publicsuffix.PublicSuffix(d); icann || strings.IndexByte(etld, '.') >= 0 {
			out = append(out, d)
		}
	}
	return out
}
