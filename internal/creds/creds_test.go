package creds

import (
	"testing"

	"github.com/JA3G3R/agneyastra/internal/report"
)

func TestSetOrderingAndCustomToken(t *testing.T) {
	s := New()
	if len(s.Levels()) != 1 || s.Levels()[0].Name != report.AuthPublic {
		t.Fatal("new set must start with public level")
	}
	s.Add(report.AuthAnon, "anon-tok")
	// Regression: the old store switched on "custom" while the type list said
	// "custom-token", so custom tokens were silently dropped. Verify they stick.
	s.Add(report.AuthCustom, "custom-tok")

	if !s.Has(report.AuthCustom) || s.Token(report.AuthCustom) != "custom-tok" {
		t.Fatal("custom-token credential was not stored")
	}
	levels := s.Levels()
	if len(levels) != 3 || levels[0].Name != report.AuthPublic || levels[1].Name != report.AuthAnon || levels[2].Name != report.AuthCustom {
		t.Fatalf("levels out of order: %+v", levels)
	}

	// Empty tokens and duplicate/public adds are ignored.
	s.Add(report.AuthAnon, "dup")
	s.Add("signup", "")
	s.Add(report.AuthPublic, "x")
	if len(s.Levels()) != 3 {
		t.Fatalf("expected 3 levels after no-op adds, got %d", len(s.Levels()))
	}
}
