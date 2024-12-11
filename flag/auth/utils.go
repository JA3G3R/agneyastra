package auth

import (
	"fmt"
	"math/rand"
	"time"
)

func generateRandomEmail() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const emailLength = 10
	rand.Seed(time.Now().UnixNano())

	email := make([]byte, emailLength)
	for i := range email {
		email[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return fmt.Sprintf("%s@example.com", string(email))
}

func generateRandomPassword() string {
	const passwordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	const passwordLength = 12
	rand.Seed(time.Now().UnixNano())

	password := make([]byte, passwordLength)
	for i := range password {
		password[i] = passwordChars[rand.Intn(len(passwordChars))]
	}
	return string(password)
}
