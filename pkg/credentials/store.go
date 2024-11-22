package credentials

import (
	"sync"
)

type CredentialStore struct {
	mu                  sync.RWMutex
	AnonymousToken      string
	CustomAuthToken     string
	SignUpToken         string
	UserDefinedToken    string
	UserCredentialsToken string
}

var CredTypes = []string{"public", "user_credentials","user_defined","signup","anon", "custom-token"}

var store *CredentialStore
var once sync.Once

// Initialize the credential store (singleton)
func GetCredentialStore() *CredentialStore {
	once.Do(func() {
		store = &CredentialStore{}
	})
	return store
}

// Set a token by type
func (c *CredentialStore) SetToken(tokenType string, token string)  {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch tokenType {
	case "anon":
		c.AnonymousToken = token
	case "custom":
		c.CustomAuthToken = token
	case "signup":
		c.SignUpToken = token
	case "user_defined":
		c.UserDefinedToken = token
	case "user_credentials":
		c.UserCredentialsToken = token
	default:
		// Handle invalid token types
	}
}

// Get a token by type
func (c *CredentialStore) GetToken(tokenType string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch tokenType {
	case "anon":
		return c.AnonymousToken
	case "custom":
		return c.CustomAuthToken
	case "signup":
		return c.SignUpToken
	case "user_defined":
		return c.UserDefinedToken
	case "user_credentials":
		return c.UserCredentialsToken
	default:
		return ""
	}
}
