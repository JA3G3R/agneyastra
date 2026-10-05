// Package google assesses the blast radius of a generic Google API key by
// probing every Google service that accepts a bare `?key=` credential. Each
// probe is a single, benign, read-style request; the ones that succeed are the
// services an attacker could abuse (billing/quota drain or data access) if the
// key were leaked and left unrestricted.
package google

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

// Scan runs the whole catalog concurrently and returns one entry per *enabled*
// service (the actual blast radius). Results are stable-sorted by severity then
// name by the caller's report.Finalize; here we just collect.
func Scan(ctx context.Context, client *httpx.Client, apiKey string) []report.BlastRadiusEntry {
	const workers = 10
	sem := make(chan struct{}, workers)
	var (
		mu  sync.Mutex
		out []report.BlastRadiusEntry
		wg  sync.WaitGroup
	)

	for _, ep := range catalog {
		wg.Add(1)
		go func(ep endpoint) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := strings.ReplaceAll(ep.url, "{KEY}", apiKey)
			var resp *httpx.Response
			var err error
			if ep.method == "POST" {
				h := map[string]string{}
				if ep.contentType != "" {
					h["Content-Type"] = ep.contentType
				}
				for k, v := range ep.headers {
					h[k] = v
				}
				resp, err = client.Do(ctx, "POST", url, []byte(ep.body), h)
			} else {
				resp, err = client.Get(ctx, url, ep.headers)
			}
			if err != nil || resp == nil {
				return
			}
			if !ep.enabled(resp) {
				return
			}
			mu.Lock()
			out = append(out, report.BlastRadiusEntry{
				API:         ep.name,
				Category:    ep.category,
				Enabled:     true,
				Severity:    report.Severity(ep.severity),
				Detail:      fmt.Sprintf("Key is unrestricted for the %s API — usable by anyone who has the key, billed to the project owner.", ep.name),
				PoC:         poc(ep, url),
				Remediation: ep.remediation,
			})
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return out
}

func poc(ep endpoint, url string) string {
	if ep.method == "POST" {
		var b strings.Builder
		b.WriteString("curl -X POST '" + url + "'")
		if ep.contentType != "" {
			b.WriteString(" -H 'Content-Type: " + ep.contentType + "'")
		}
		for k, v := range ep.headers {
			b.WriteString(" -H '" + k + ": " + v + "'")
		}
		if ep.body != "" {
			b.WriteString(" -d '" + ep.body + "'")
		}
		return b.String()
	}
	return "curl '" + url + "'"
}
