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
	cookie, err := req.Cookie(SessionCookieName)
	if err != nil {
		originalRequestURL := url.QueryEscape(req.URL.String())
		http.Redirect(rw, req, fmt.Sprintf("%s/auth/login?redirect=%s", p.appBaseUrl, originalRequestURL), http.StatusFound)
		return
	}

	sessionID := cookie.Value
	verifyURL := fmt.Sprintf("%s/badger/verify-user?sessionId=%s", p.apiBaseUrl, sessionID)

	resp, err := http.Get(verifyURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			http.Redirect(rw, req, p.appBaseUrl, http.StatusFound)
		} else {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	p.next.ServeHTTP(rw, req)
}
