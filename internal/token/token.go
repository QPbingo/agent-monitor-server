// Package token manages the daemon authentication token.
// Token is a 256-bit random value stored as Base64 in ~/.agent-monitor/local-token.
// All API/WS endpoints require it; hooks embed it in each event.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

const (
	TokenFileName = "local-token"
	TokenSize     = 32
)

func Generate() (string, error) {
	b := make([]byte, TokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func Read(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, TokenFileName))
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	return string(data), nil
}

func Write(dir string, token string) error {
	path := filepath.Join(dir, TokenFileName)
	return os.WriteFile(path, []byte(token), 0600)
}

func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
