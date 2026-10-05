package firebase

import (
	"testing"

	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

func resp(status int, body string) *httpx.Response {
	return &httpx.Response{Status: status, Body: []byte(body)}
}

func TestBucketAbsent(t *testing.T) {
	cases := []struct {
		name string
		r    *httpx.Response
		want bool
	}{
		{"404 absent", resp(404, `{"error":{"code":404}}`), true},
		{"400 does not exist", resp(400, `{"error":{"message":"The specified bucket does not exist."}}`), true},
		{"403 exists but locked", resp(403, `{"error":{"code":403,"message":"Permission denied."}}`), false},
		{"200 open", resp(200, `{"items":[]}`), false},
	}
	for _, c := range cases {
		if got := bucketAbsent(c.r); got != c.want {
			t.Errorf("%s: bucketAbsent = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRTDBAbsent(t *testing.T) {
	cases := []struct {
		name string
		r    *httpx.Response
		want bool
	}{
		{"404", resp(404, `404 Not Found`), true},
		{"423 disabled", resp(423, ``), true},
		{"401 locked", resp(401, `{"error":"Permission denied"}`), false},
		{"200 open", resp(200, `{"a":true}`), false},
	}
	for _, c := range cases {
		if got := rtdbAbsent(c.r); got != c.want {
			t.Errorf("%s: rtdbAbsent = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClassifyFirestore(t *testing.T) {
	cases := []struct {
		name                             string
		r                                *httpx.Response
		wAbsent, wDisabled, wDenied, wOK bool
	}{
		{"ok", resp(200, `{}`), false, false, false, true},
		{"not found -> absent", resp(404, `{"error":{"status":"NOT_FOUND"}}`), true, false, false, false},
		{"service disabled", resp(403, `{"error":{"status":"PERMISSION_DENIED","message":"Cloud Firestore API has not been used in project 123 before or it is disabled"}}`), false, true, false, false},
		{"rules denied", resp(403, `{"error":{"status":"PERMISSION_DENIED","message":"Missing or insufficient permissions."}}`), false, false, true, false},
	}
	for _, c := range cases {
		a, d, dn, ok := classifyFirestore(c.r)
		if a != c.wAbsent || d != c.wDisabled || dn != c.wDenied || ok != c.wOK {
			t.Errorf("%s: got (absent=%v disabled=%v denied=%v ok=%v), want (%v %v %v %v)",
				c.name, a, d, dn, ok, c.wAbsent, c.wDisabled, c.wDenied, c.wOK)
		}
	}
}

func TestBucketNames(t *testing.T) {
	got := bucketNames("myproj")
	if len(got) != 2 || got[0] != "myproj.firebasestorage.app" || got[1] != "myproj.appspot.com" {
		t.Fatalf("bucketNames(myproj) = %v", got)
	}
	if got := bucketNames("custom.appspot.com"); len(got) != 1 || got[0] != "custom.appspot.com" {
		t.Fatalf("bucketNames(custom.appspot.com) = %v", got)
	}
}

func TestSeverity(t *testing.T) {
	if readSeverity(report.AuthPublic, true) != report.SevHigh {
		t.Error("public read with data should be high")
	}
	if readSeverity(report.AuthPublic, false) != report.SevMedium {
		t.Error("public read empty should be medium")
	}
	if readSeverity(report.AuthCustom, true) != report.SevLow {
		t.Error("custom-token read should be low (attacker must possess a token)")
	}
	if writeSeverity(report.AuthAnon) != report.SevHigh {
		t.Error("anon write should be high (self-serviceable)")
	}
	if writeSeverity(report.AuthUserCreds) != report.SevLow {
		t.Error("user-creds write should be low")
	}
}
