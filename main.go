package badger

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

const SessionCookieName = "session"

type Config struct {
	AppBaseUrl string `json:"appBaseUrl"`
	APIBaseUrl string `json:"apiBaseUrl"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Badger struct {
	next       http.Handler
	name       string
	appBaseUrl string
	apiBaseUrl string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:       next,
		name:       name,
		appBaseUrl: config.AppBaseUrl,
		apiBaseUrl: config.APIBaseUrl,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if the session cookie exists
	cookie, err := req.Cookie(SessionCookieName)
	if err != nil {
		// No session cookie, redirect to login
		originalRequestURL := url.QueryEscape(fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.RequestURI()))
		http.Redirect(rw, req, fmt.Sprintf("%s/auth/login?redirect=%s", p.appBaseUrl, originalRequestURL), http.StatusFound)
		return
	}

	// Verify the user with the session ID
	sessionID := cookie.Value
	verifyURL := fmt.Sprintf("%s/badger/verify-user?sessionId=%s", p.apiBaseUrl, sessionID)

	resp, err := http.Get(verifyURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		// If unauthorized (401), redirect to the homepage
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			http.Redirect(rw, req, p.appBaseUrl, http.StatusFound)
		} else {
			// Handle other errors, possibly log them (you can adjust the error handling here)
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	p.next.ServeHTTP(rw, req)
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
