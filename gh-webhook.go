package github_webhook_middleware

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"crypto/hmac"
	"crypto/sha256"
)

type Config struct {
	Secret       string `json:"secret,omitempty" loggable:"false"`
	AuthHeader   string `json:"authHeader,omitempty"`
	HeaderPrefix string `json:"headerPrefix,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type GHW struct {
	next         http.Handler
	name         string
	secret       string
	authHeader   string
	headerPrefix string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Secret) == 0 {
		config.Secret = os.Getenv("GH_WEBHOOK_SECRET")
	}
	if len(config.Secret) == 0 {
		config.Secret = "SECRET"
	}
	if len(config.AuthHeader) == 0 {
		config.AuthHeader = "X-Hub-Signature-256"
	}
	if len(config.HeaderPrefix) == 0 {
		config.HeaderPrefix = "sha256="
	}

	return &GHW{
		next:         next,
		name:         name,
		secret:       config.Secret,
		authHeader:   config.AuthHeader,
		headerPrefix: config.HeaderPrefix,
	}, nil
}

func (g *GHW) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(g.authHeader)

	if len(headerToken) == 0 {
		http.Error(res, "Request error", http.StatusUnauthorized)
		return
	}

	token, preprocessError := preprocessToken(headerToken, g.headerPrefix)
	if preprocessError != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	// https://stackoverflow.com/a/43021236/1200847
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	verified, verificationError := verifyToken(token, g.secret, body)
	if verificationError != nil {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
		return
	}

	if verified {
		// could remove header here if we wanted to
		g.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
}

// verifyToken Verifies jwt token with secret
func verifyToken(token string, secret string, body []byte) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	decodedVerification, errDecode := hex.DecodeString(token)
	if errDecode != nil {
		return false, errDecode
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true, nil
	}

	return false, nil
}

// preprocessToken Takes the request header string, strips prefix and whitespaces and returns a Token
func preprocessToken(reqHeader string, prefix string) (string, error) {
	cleanedString := strings.TrimPrefix(reqHeader, prefix)
	cleanedString = strings.TrimSpace(cleanedString)

	if len(cleanedString)-len(reqHeader) >= 0 {
		return "", fmt.Errorf("invalid token")
	}

	return cleanedString, nil
}
