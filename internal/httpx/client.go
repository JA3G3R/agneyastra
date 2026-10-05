// Package httpx provides a single shared, tuned HTTP client and small helpers
// used by every check in agneyastra. Centralising the client lets us keep
// connections alive across the many probes fired per API key and apply
// consistent timeouts instead of the per-request default clients the old code
// created on every call.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client wraps *http.Client with convenience helpers. It is safe for concurrent
// use by multiple goroutines.
type Client struct {
	hc *http.Client
}

// New returns a Client with a connection-pooled transport suitable for firing
// many small requests concurrently against a handful of Google hosts.
func New(perRequestTimeout time.Duration) *Client {
	if perRequestTimeout <= 0 {
		perRequestTimeout = 15 * time.Second
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Client{
		hc: &http.Client{
			Transport: tr,
			Timeout:   perRequestTimeout,
			// We inspect status codes and redirects ourselves (e.g. the Places
			// Photo endpoint signals success with a 302), so never auto-follow.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Response is a small, fully-read snapshot of an HTTP response. Bodies are read
// eagerly and capped so callers never have to remember to close them and a
// hostile/huge response can't exhaust memory.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

const maxBodyBytes = 2 << 20 // 2 MiB is plenty for the JSON control responses we parse.

// Do executes a request built from the given parameters. headers and the body
// are optional. It never returns a non-nil Response together with an error.
func (c *Client) Do(ctx context.Context, method, url string, body []byte, headers map[string]string) (*Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

// Get is a convenience wrapper for GET requests.
func (c *Client) Get(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, url, nil, headers)
}

// PostJSON issues a POST with a JSON body and the appropriate content type.
func (c *Client) PostJSON(ctx context.Context, url string, payload any, headers map[string]string) (*Response, error) {
	var b []byte
	if payload != nil {
		var err error
		b, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return c.Do(ctx, http.MethodPost, url, b, h)
}

// JSON unmarshals the response body into v. It tolerates empty bodies.
func (r *Response) JSON(v any) error {
	if len(bytes.TrimSpace(r.Body)) == 0 {
		return nil
	}
	return json.Unmarshal(r.Body, v)
}

// Text returns the body as a string (used for substring probes on error blobs).
func (r *Response) Text() string { return string(r.Body) }

// BodyContains reports whether the (case-insensitive) needle appears in the body.
func (r *Response) BodyContains(needle string) bool {
	return strings.Contains(strings.ToLower(string(r.Body)), strings.ToLower(needle))
}

// BearerHeader builds an Authorization header map for the given token, or an
// empty map for the public (no-token) level.
func BearerHeader(token string) map[string]string {
	if token == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + token}
}
