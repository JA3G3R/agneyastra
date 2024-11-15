package services

// auth service structs

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

// storage bucket service structs

type KeysResponse struct {
	Prefixes []string `json:"prefixes"`
	Items    []Item   `json:"items"`
}

type KeysResponseRecursive struct {
	Prefixes map[string]KeysResponseRecursive `json:"prefixes"`
	Items    []Item   `json:"items"`
}
// Struct to represent each item (file)
type Item struct {
	Name   string `json:"name"`
	Bucket string `json:"bucket"`
}

type UploadCheckResult struct {
	Bucket string
	Success bool
	Error string
}

type BucketData struct {
	Bucket string
	Data   KeysResponseRecursive
}

type DeleteCheckResult struct {
	Bucket   string
	Success  bool
	Error    string
	FileName string
}

// Firestore

type FirestoreDocumentAdded struct {
	DocumentID string `json:"documentID"`
	DocumentContent interface{} `json:"documentContent"`
	ProjectID string `json:"projectId"`
}

// rtdb service structs
type Message struct {
    T string // Message type
    D Data   // Data part of the message
}

// Data represents the inner data structure within a Message.
type Data struct {
    R int                    // Request ID
    A string                 // Action (e.g., "put", "get")
    B map[string]interface{} // Body containing path and data
}