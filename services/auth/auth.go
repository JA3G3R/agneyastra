package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/JA3G3R/agneyastra/pkg/credentials"
	"github.com/JA3G3R/agneyastra/services"
)

// CheckSignInWithPassword checks if email/password sign-in is enabled
func SignInWithPassword(apiKey, email, password string) (services.Status, *LoginResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)

	// Create request body
	payload := SignInWithPasswordRequest{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return services.StatusError, nil, fmt.Errorf("failed to sign in with email/password, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signInResp LoginResponse
	err = json.Unmarshal(body, &signInResp)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If idToken is present, email/password sign-in is enabled
	if signInResp.IDToken != "" {
		store := credentials.GetCredentialStore()
		store.SetToken("user_credentials", signInResp.IDToken)
		fmt.Println("Email/Password sign-in successful!")
		return services.StatusVulnerable, &signInResp, nil
	}

	return services.StatusSafe, nil, nil
}

// CheckLoginWithCustomToken checks if login with custom token is enabled
func LoginWithCustomToken(apiKey, customToken string) (services.Status, *LoginResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=%s", apiKey)

	// Create request body
	payload := CustomTokenRequest{
		Token:            customToken,
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return services.StatusError, nil, fmt.Errorf("failed to log in with custom token, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var customTokenResp LoginResponse
	err = json.Unmarshal(body, &customTokenResp)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If idToken is present, login with custom token is enabled
	if customTokenResp.IDToken != "" {
		store := credentials.GetCredentialStore()
		store.SetToken("custom", customTokenResp.IDToken)
		fmt.Println("Custom token login successful!")
		return services.StatusVulnerable, &customTokenResp, nil
	}

	return services.StatusSafe, nil, nil
}

// CheckSendSignInLink checks if sending a sign-in link to email is enabled
func SendSignInLink(apiKey, email string) (services.Status, *SendSignInLinkResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=%s", apiKey)

	// Create request body
	payload := SendSignInLinkRequest{
		RequestType:        "EMAIL_SIGNIN",
		Email:              email,
		ContinueURL:        "http://localhost:8888/completeAuth", // Modify as needed
		CanHandleCodeInApp: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return services.StatusError, nil, fmt.Errorf("failed to send sign-in link, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signInLinkResp SendSignInLinkResponse
	err = json.Unmarshal(body, &signInLinkResp)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If a kind and email are present, the sign-in link feature is enabled
	if signInLinkResp.Kind != "" && signInLinkResp.Email != "" {
		log.Printf("Sign-in link sent to email: %s\n", signInLinkResp.Email)
		return services.StatusVulnerable, &signInLinkResp, nil
	}

	return services.StatusSafe, nil, nil
}

func SignUp(apiKey, email, password string) (services.Status, *LoginResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)
	// fmt.Printf("Signing up with email: %s, password: %s\n", email, password)
	// Create request body
	payload := EmailSignUpRequest{
		Email:            email,
		Password:         password,
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return services.StatusError, nil, fmt.Errorf("failed to sign up with email/password, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signUpResp LoginResponse
	err = json.Unmarshal(body, &signUpResp)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If an idToken is present, email/password authentication is allowed
	if signUpResp.IDToken != "" {
		store := credentials.GetCredentialStore()
		store.SetToken("signup", signUpResp.IDToken)
		log.Printf("Email/Password sign-up enabled! Session Token: %s\n", signUpResp.IDToken)
		return services.StatusVulnerable, &signUpResp, nil
	}

	return services.StatusSafe, nil, nil
}

// CheckAnonymousAuth checks whether the project allows anonymous authentication
func AnonymousAuth(apiKey string) (services.Status, *LoginResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)

	// Create request body
	payload := SignUpRequest{
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return services.StatusError, nil, fmt.Errorf("failed to sign up anonymously, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var anonsignUpResp LoginResponse
	err = json.Unmarshal(body, &anonsignUpResp)
	if err != nil {
		return services.StatusError, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If an idToken is present, anonymous authentication is allowed
	if anonsignUpResp.IDToken != "" {
		store := credentials.GetCredentialStore()
		store.SetToken("anon", anonsignUpResp.IDToken)
		// log.Printf("Anonymous login enabled! Session Token: %s\n", signUpResp.IDToken)
		return services.StatusVulnerable, &anonsignUpResp, nil
	}

	return services.StatusSafe, nil, nil
}