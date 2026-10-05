// Package secrets performs a lightweight scan of data pulled from readable
// RTDB/Storage resources. It ships an offline default detector set (the old code
// downloaded regexes from a third-party URL at runtime). For deep secret
// analysis, feed the dumped data through the sibling `secretscan`/`loot` tools,
// which carry hundreds of detectors.
package secrets

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultPatterns are high-signal, low-false-positive detectors.
var defaultPatterns = map[string]string{
	"google_api_key":      `AIza[0-9A-Za-z_\-]{35}`,
	"gcp_service_account": `"type"\s*:\s*"service_account"`,
	"aws_access_key_id":   `AKIA[0-9A-Z]{16}`,
	"private_key":         `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
	"jwt":                 `eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`,
	"slack_token":         `xox[baprs]-[0-9A-Za-z\-]{10,48}`,
	"stripe_secret_key":   `sk_live_[0-9A-Za-z]{24,}`,
	"github_token":        `gh[pousr]_[0-9A-Za-z]{36,}`,
	"twilio_sid":          `AC[0-9a-fA-F]{32}`,
	"sendgrid_key":        `SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`,
}

const maxMatchesPerType = 20

// Compile returns the detector set. If regexFile is empty the defaults are used;
// otherwise a JSON or YAML map of name->pattern is loaded.
func Compile(regexFile string) (map[string]*regexp.Regexp, error) {
	raw := defaultPatterns
	if regexFile != "" {
		data, err := os.ReadFile(regexFile)
		if err != nil {
			return nil, err
		}
		loaded := map[string]string{}
		if strings.HasSuffix(regexFile, ".yaml") || strings.HasSuffix(regexFile, ".yml") {
			if err := yaml.Unmarshal(data, &loaded); err != nil {
				return nil, err
			}
		} else if err := json.Unmarshal(data, &loaded); err != nil {
			return nil, err
		}
		raw = loaded
	}
	out := make(map[string]*regexp.Regexp, len(raw))
	for name, pat := range raw {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // skip malformed patterns rather than abort the whole scan
		}
		out[name] = re
	}
	return out, nil
}

// Extract runs every detector over data and returns type -> unique matches.
func Extract(compiled map[string]*regexp.Regexp, data []byte) map[string][]string {
	out := map[string][]string{}
	for name, re := range compiled {
		matches := re.FindAllString(string(data), -1)
		if len(matches) == 0 {
			continue
		}
		seen := map[string]bool{}
		var uniq []string
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			uniq = append(uniq, m)
			if len(uniq) >= maxMatchesPerType {
				break
			}
		}
		sort.Strings(uniq)
		out[name] = uniq
	}
	return out
}
