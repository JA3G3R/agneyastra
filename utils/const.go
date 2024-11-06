package utils

// Structs for JSON responses
type ProjectConfig struct {
	ProjectID          string   `json:"projectId"`
	AuthorizedDomains  []string `json:"authorizedDomains"`
}


type SignUpRequest struct {
	ReturnSecureToken bool `json:"returnSecureToken"`
}

type SignUpResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

type EmailSignUpRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ReturnSecureToken bool  `json:"returnSecureToken"`
}

type EmailSignUpResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}
type SendSignInLinkRequest struct {
	RequestType        string `json:"requestType"`
	Email              string `json:"email"`
	ContinueURL        string `json:"continueUrl"`
	CanHandleCodeInApp bool   `json:"canHandleCodeInApp"`
}

type SendSignInLinkResponse struct {
	Kind  string `json:"kind"`
	Email string `json:"email"`
}

type CustomTokenRequest struct {
	Token            string `json:"token"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type CustomTokenResponse struct {
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
}

type SignInWithPasswordRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type SignInWithPasswordResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
	Registered   bool   `json:"registered"`
}

type BucketData struct {
	Domain string
	Keys   KeysResponse
}

type DeleteCheckResult struct {
	Bucket   string
	Success  bool
	Error    string
	FileName string
}