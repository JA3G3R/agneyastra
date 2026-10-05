// Package creds holds the authentication tokens obtained for a single API key,
// ordered from least to most privileged. The old code used a process-wide
// singleton credential store, which meant tokens minted for one key leaked into
// checks for every other key during a multi-key scan. A Set is created per key
// and never shared, so escalation is always scoped to the key under test.
package creds

import "github.com/JA3G3R/agneyastra/internal/report"

// Level pairs an auth-level name with the bearer token that reaches it. The
// public level always has an empty token.
type Level struct {
	Name  string
	Token string
}

// Set is an ordered collection of auth levels for one key. It is built up by the
// auth stage and then read by the service checks. It is not safe for concurrent
// mutation, but the scanner always fully populates a Set before sharing it for
// read-only iteration.
type Set struct {
	levels []Level
	index  map[string]string
}

// New returns a Set that already contains the public (unauthenticated) level.
func New() *Set {
	return &Set{
		levels: []Level{{Name: report.AuthPublic, Token: ""}},
		index:  map[string]string{report.AuthPublic: ""},
	}
}

// Add records a token for a named auth level. Empty tokens and duplicate levels
// are ignored so callers can add unconditionally.
func (s *Set) Add(name, token string) {
	if token == "" || name == report.AuthPublic {
		return
	}
	if _, ok := s.index[name]; ok {
		return
	}
	s.index[name] = token
	s.levels = append(s.levels, Level{Name: name, Token: token})
}

// Levels returns the auth levels in ascending privilege order (public first).
func (s *Set) Levels() []Level { return s.levels }

// Has reports whether a token exists for the given level.
func (s *Set) Has(name string) bool {
	t, ok := s.index[name]
	return ok && t != ""
}

// Token returns the bearer token for a level (empty for public / unknown).
func (s *Set) Token(name string) string { return s.index[name] }
