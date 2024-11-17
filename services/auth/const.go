package auth

type SignUpRequest struct {
	ReturnSecureToken bool `json:"returnSecureToken"`
}

type EmailSignUpRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ReturnSecureToken bool  `json:"returnSecureToken"`
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

type SignInWithPasswordRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type LoginResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
	Registered   bool   `json:"registered"`
}
