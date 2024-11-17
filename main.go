package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const AppSSOSessionCookieName = "session"
const ResourceSessionCookieName = "resource_session"

type Config struct {
	AppBaseUrl string `json:"appBaseUrl"`
	APIBaseUrl string `json:"apiBaseUrl"`
}

type CookieData struct {
	Session         *string `json:"session"`
	ResourceSession *string `json:"resource_session"`
}

type VerifyBody struct {
	Cookies            CookieData `json:"cookies"`
	OriginalRequestURL string     `json:"originalRequestURL"`
	RequestScheme      *string    `json:"scheme"`
	RequestHost        *string    `json:"host"`
	RequestPath        *string    `json:"path"`
	RequestMethod      *string    `json:"method"`
	TLS                bool       `json:"tls"`
}

type VerifyResponse struct {
	Valid       bool    `json:"valid"`
	RedirectURL *string `json:"redirectUrl"`
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
	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)
	cookies := extractCookies(req)

	originalRequestURL := url.QueryEscape(fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.RequestURI()))

	cookieData := VerifyBody{
		Cookies: CookieData{
			Session:         cookies.Session,
			ResourceSession: cookies.ResourceSession,
		},
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
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

	if result.RedirectURL != nil && *result.RedirectURL != "" {
		http.Redirect(rw, req, *result.RedirectURL, http.StatusFound)
		return
	}

	if !result.Valid { // only do this if for some reason the API doesn't return a redirect and it's not valid
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(rw, req)
}

func extractCookies(req *http.Request) CookieData {
	var cookies CookieData

	if appSSOSessionCookie, err := req.Cookie(AppSSOSessionCookieName); err == nil {
		cookies.Session = &appSSOSessionCookie.Value
	}

	if resourceSessionCookie, err := req.Cookie(ResourceSessionCookieName); err == nil {
		cookies.ResourceSession = &resourceSessionCookie.Value
	}

	return cookies
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
