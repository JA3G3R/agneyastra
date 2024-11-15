package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// CheckSignInWithPassword checks if email/password sign-in is enabled
func CheckSignInWithPassword(apiKey, email, password string) (bool, *SignInWithPasswordResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)

	// Create request body
	payload := SignInWithPasswordRequest{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("failed to sign in with email/password, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signInResp SignInWithPasswordResponse
	err = json.Unmarshal(body, &signInResp)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If idToken is present, email/password sign-in is enabled
	if signInResp.IDToken != "" {
		fmt.Println("Email/Password sign-in successful!")
		return true, &signInResp, nil
	}

	return false, nil, nil
}

// CheckLoginWithCustomToken checks if login with custom token is enabled
func CheckLoginWithCustomToken(apiKey, customToken string) (bool, *CustomTokenResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=%s", apiKey)

	// Create request body
	payload := CustomTokenRequest{
		Token:            customToken,
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("failed to log in with custom token, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var customTokenResp CustomTokenResponse
	err = json.Unmarshal(body, &customTokenResp)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If idToken is present, login with custom token is enabled
	if customTokenResp.IDToken != "" {
		fmt.Println("Custom token login successful!")
		return true, &customTokenResp, nil
	}

	return false, nil, nil
}

// CheckSendSignInLink checks if sending a sign-in link to email is enabled
func CheckSendSignInLink(apiKey, email string) (bool, *SendSignInLinkResponse, error) {
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
		return false, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("failed to send sign-in link, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signInLinkResp SendSignInLinkResponse
	err = json.Unmarshal(body, &signInLinkResp)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If a kind and email are present, the sign-in link feature is enabled
	if signInLinkResp.Kind != "" && signInLinkResp.Email != "" {
		fmt.Printf("Sign-in link sent to email: %s\n", signInLinkResp.Email)
		return true, &signInLinkResp, nil
	}

	return false, nil, nil
}

func SignUp(apiKey, email, password string) (bool, *EmailSignUpResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)

	// Create request body
	payload := EmailSignUpRequest{
		Email:            email,
		Password:         password,
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("failed to sign up with email/password, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signUpResp EmailSignUpResponse
	err = json.Unmarshal(body, &signUpResp)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If an idToken is present, email/password authentication is allowed
	if signUpResp.IDToken != "" {
		fmt.Printf("Email/Password sign-up enabled! Session Token: %s\n", signUpResp.IDToken)
		return true, &signUpResp, nil
	}

	return false, nil, nil
}

// CheckAnonymousAuth checks whether the project allows anonymous authentication
func CheckAnonymousAuth(apiKey string) (bool, *SignUpResponse, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)

	// Create request body
	payload := SignUpRequest{
		ReturnSecureToken: true,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send POST request to the Firebase Auth API
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("failed to sign up anonymously, status code: %d", resp.StatusCode)
	}

	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var signUpResp SignUpResponse
	err = json.Unmarshal(body, &signUpResp)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	// If an idToken is present, anonymous authentication is allowed
	if signUpResp.IDToken != "" {
		// fmt.Printf("Anonymous login enabled! Session Token: %s\n", signUpResp.IDToken)
		return true, &signUpResp, nil
	}

	return false, nil, nil
}