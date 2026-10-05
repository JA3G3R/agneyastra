package keyinfo

import (
	"reflect"
	"strings"
	"testing"
)

func TestProjectIDsFromDomains(t *testing.T) {
	in := []string{
		"localhost",
		"myproject.firebaseapp.com",
		"myproject.web.app", // same id via .web.app -> deduped
		"other-app.web.app",
		"example.com",         // not a firebase host -> ignored
		"a.b.firebaseapp.com", // multi-label subdomain -> ignored (not a bare project id)
	}
	got := projectIDsFromDomains(in)
	want := []string{"myproject", "other-app"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectIDsFromDomains = %v, want %v", got, want)
	}
}

func TestKeyFormatDetection(t *testing.T) {
	valid := "AIza" + strings.Repeat("a", 35) // AIza + 35 chars = 39
	if len(valid) != 39 {
		t.Fatalf("test key wrong length: %d", len(valid))
	}
	if !googleKeyRE.MatchString(valid) {
		t.Errorf("valid AIza key not recognised: %s", valid)
	}
	if googleKeyRE.MatchString("nope") {
		t.Error("non-key matched")
	}
}

func TestNumericDetection(t *testing.T) {
	if !numericRE.MatchString("104159166443") {
		t.Error("project number should be detected as numeric")
	}
	if numericRE.MatchString("my-project-123") {
		t.Error("string project id must not be numeric")
	}
}
