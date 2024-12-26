package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	APIBaseUrl                string `json:"apiBaseUrl"`
	UserSessionCookieName     string `json:"userSessionCookieName"`
	ResourceSessionCookieName string `json:"resourceSessionCookieName"`
}

type VerifyBody struct {
	Sessions           map[string]string `json:"sessions"`
	OriginalRequestURL string            `json:"originalRequestURL"`
	RequestScheme      *string           `json:"scheme"`
	RequestHost        *string           `json:"host"`
	RequestPath        *string           `json:"path"`
	RequestMethod      *string           `json:"method"`
	TLS                bool              `json:"tls"`
}

type VerifyResponse struct {
	Data struct {
		Valid       bool    `json:"valid"`
		RedirectURL *string `json:"redirectUrl"`
	} `json:"data"`
}

type Badger struct {
	next                      http.Handler
	name                      string
	apiBaseUrl                string
	userSessionCookieName     string
	resourceSessionCookieName string
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:                      next,
		name:                      name,
		apiBaseUrl:                config.APIBaseUrl,
		userSessionCookieName:     config.UserSessionCookieName,
		resourceSessionCookieName: config.ResourceSessionCookieName,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookies := p.extractCookies(req)

	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)
	originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.RequestURI())

	cookieData := VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError) // TODO: redirect to error page
		return
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound)
		return
	}

	if !result.Data.Valid {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(rw, req)
}

func (p *Badger) extractCookies(req *http.Request) map[string]string {
	cookies := make(map[string]string)

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, p.userSessionCookieName) || strings.HasPrefix(cookie.Name, p.resourceSessionCookieName) {
			cookies[cookie.Name] = cookie.Value
		}
	}

	return cookies
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
