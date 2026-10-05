package firebase

import (
	"context"
	"fmt"

	"github.com/JA3G3R/agneyastra/internal/creds"
	"github.com/JA3G3R/agneyastra/internal/httpx"
	"github.com/JA3G3R/agneyastra/internal/report"
)

const idtBase = "https://identitytoolkit.googleapis.com/v1/accounts"

// AuthConfig carries operator-supplied inputs for the auth stage.
type AuthConfig struct {
	SignupEmail    string
	SignupPassword string
	CustomToken    string
	UserEmail      string
	UserPassword   string
	SendLinkEmail  string
}

type signInResp struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

type oobResp struct {
	Kind  string `json:"kind"`
	Email string `json:"email"`
}

// Auth acquires the tokens an attacker could obtain from the key and records
// which sign-in providers are enabled. The returned credential set is scoped to
// this key alone and is what the service checks escalate through.
//
// Token acquisition (anonymous + email/password sign-up) runs by default: it is
// the core of the "auth -> privileged access" chain this tool exists to test,
// and the accounts it creates are throwaway. Sending a sign-in link emails a
// real address, so it runs only when active is true.
func Auth(ctx context.Context, client *httpx.Client, apiKey string, cfg AuthConfig, active bool) (*creds.Set, *report.AuthProviders, []report.Finding, []string) {
	cs := creds.New()
	providers := &report.AuthProviders{}
	var findings []report.Finding
	var errs []string

	// 1. Anonymous authentication.
	if tok, ok, err := signUp(ctx, client, apiKey, nil); err != "" {
		errs = append(errs, "anon auth: "+err)
	} else if ok {
		providers.Anonymous = true
		cs.Add(report.AuthAnon, tok.IDToken)
		findings = append(findings, providerFinding("Anonymous authentication enabled",
			"anon", "Any unauthenticated attacker can mint a valid Firebase ID token, satisfying rules that only check request.auth != null.",
			"Disable Anonymous sign-in in Firebase Console > Authentication > Sign-in method (unless required, and then never treat request.auth != null as authorization)."))
	}

	// 2. Email/password sign-up.
	email := cfg.SignupEmail
	if email == "" {
		email = fmt.Sprintf("agneyastra_%s@example.com", randHex(10))
	}
	password := cfg.SignupPassword
	if password == "" {
		password = "Ag3!" + randHex(16)
	}
	if tok, ok, err := signUp(ctx, client, apiKey, map[string]any{
		"email": email, "password": password, "returnSecureToken": true,
	}); err != "" {
		errs = append(errs, "signup: "+err)
	} else if ok {
		providers.EmailPasswordSignup = true
		cs.Add(report.AuthSignup, tok.IDToken)
		findings = append(findings, providerFinding("Public email/password sign-up enabled",
			"signup", "Anyone can self-register an account, gaining an authenticated context to abuse rules that trust any signed-in user.",
			"Restrict sign-up (Identity Platform / Auth settings) or ensure rules check specific roles/UIDs rather than mere authentication."))
	}

	// 3. Custom-token login (only when the operator supplied a token).
	if cfg.CustomToken != "" {
		if tok, ok, err := signInWithCustomToken(ctx, client, apiKey, cfg.CustomToken); err != "" {
			errs = append(errs, "custom-token: "+err)
		} else if ok {
			providers.CustomToken = true
			cs.Add(report.AuthCustom, tok.IDToken)
			findings = append(findings, providerFinding("Custom-token sign-in accepted",
				"custom-token", "The supplied custom token was accepted, yielding an authenticated session.",
				"Rotate the signing credentials and verify custom-token minting is not exposed."))
		}
	}

	// 4. Email/password sign-in with operator-supplied credentials.
	if cfg.UserEmail != "" && cfg.UserPassword != "" {
		if tok, ok, err := signInWithPassword(ctx, client, apiKey, cfg.UserEmail, cfg.UserPassword); err != "" {
			errs = append(errs, "user-creds sign-in: "+err)
		} else if ok {
			providers.PasswordSignin = true
			cs.Add(report.AuthUserCreds, tok.IDToken)
		}
	}

	// 5. Email-link (sends a real email -> active only).
	if active && cfg.SendLinkEmail != "" {
		if ok, err := sendSignInLink(ctx, client, apiKey, cfg.SendLinkEmail); err != "" {
			errs = append(errs, "send-signin-link: "+err)
		} else if ok {
			providers.EmailLink = true
			f := providerFinding("Email-link sign-in enabled (email delivered)",
				"email-link", "The project delivered a sign-in link to an operator-controlled address, so it can be abused to send Google-hosted phishing/sign-in emails.",
				"Disable Email link sign-in if unused; otherwise restrict authorized continue URLs.")
			f.Severity = report.SevLow
			f.Evidence = map[string]any{"email": cfg.SendLinkEmail}
			findings = append(findings, f)
		}
	}

	return cs, providers, findings, errs
}

// providerFinding builds an informational finding for an enabled auth provider.
// These are context, not impact: severity stays info unless a token later
// unlocks a service, in which case the service finding carries the real impact.
func providerFinding(title, provider, detail, remedy string) report.Finding {
	return report.Finding{
		Service:     "firebase.auth",
		Check:       "provider",
		Resource:    provider,
		Status:      report.StatusVulnerable,
		Severity:    report.SevInfo,
		Confidence:  report.ConfConfirmed,
		Title:       title,
		Detail:      detail,
		Remediation: remedy,
	}
}

func signUp(ctx context.Context, client *httpx.Client, apiKey string, payload map[string]any) (*signInResp, bool, string) {
	if payload == nil {
		payload = map[string]any{"returnSecureToken": true}
	}
	resp, err := client.PostJSON(ctx, idtBase+":signUp?key="+apiKey, payload, nil)
	if err != nil {
		return nil, false, err.Error()
	}
	if resp.Status != 200 {
		return nil, false, "" // provider simply disabled; not an operational error
	}
	var out signInResp
	if err := resp.JSON(&out); err != nil {
		return nil, false, err.Error()
	}
	return &out, out.IDToken != "", ""
}

func signInWithCustomToken(ctx context.Context, client *httpx.Client, apiKey, token string) (*signInResp, bool, string) {
	resp, err := client.PostJSON(ctx, idtBase+":signInWithCustomToken?key="+apiKey,
		map[string]any{"token": token, "returnSecureToken": true}, nil)
	if err != nil {
		return nil, false, err.Error()
	}
	if resp.Status != 200 {
		return nil, false, ""
	}
	var out signInResp
	if err := resp.JSON(&out); err != nil {
		return nil, false, err.Error()
	}
	return &out, out.IDToken != "", ""
}

func signInWithPassword(ctx context.Context, client *httpx.Client, apiKey, email, password string) (*signInResp, bool, string) {
	resp, err := client.PostJSON(ctx, idtBase+":signInWithPassword?key="+apiKey,
		map[string]any{"email": email, "password": password, "returnSecureToken": true}, nil)
	if err != nil {
		return nil, false, err.Error()
	}
	if resp.Status != 200 {
		return nil, false, ""
	}
	var out signInResp
	if err := resp.JSON(&out); err != nil {
		return nil, false, err.Error()
	}
	return &out, out.IDToken != "", ""
}

func sendSignInLink(ctx context.Context, client *httpx.Client, apiKey, email string) (bool, string) {
	resp, err := client.PostJSON(ctx, idtBase+":sendOobCode?key="+apiKey, map[string]any{
		"requestType":        "EMAIL_SIGNIN",
		"email":              email,
		"continueUrl":        "https://localhost/agneyastra",
		"canHandleCodeInApp": true,
	}, nil)
	if err != nil {
		return false, err.Error()
	}
	if resp.Status != 200 {
		return false, ""
	}
	var out oobResp
	if err := resp.JSON(&out); err != nil {
		return false, err.Error()
	}
	return out.Email != "" || out.Kind != "", ""
}
