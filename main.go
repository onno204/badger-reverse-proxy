package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Config struct {
	APIBaseUrl                string `json:"apiBaseUrl"`
	SessionQueryParameter     string `json:"sessionQueryParameter"`
	UserSessionCookieName     string `json:"userSessionCookieName"`
	ResourceSessionCookieName string `json:"resourceSessionCookieName"`
}

type SessionData struct {
	Session         *string `json:"session"`
	ResourceSession *string `json:"resource_session"`
}

type VerifyBody struct {
	Sessions           SessionData `json:"session"`
	OriginalRequestURL string      `json:"originalRequestURL"`
	RequestScheme      *string     `json:"scheme"`
	RequestHost        *string     `json:"host"`
	RequestPath        *string     `json:"path"`
	RequestMethod      *string     `json:"method"`
	TLS                bool        `json:"tls"`
}

type VerifyResponse struct {
	Valid       bool    `json:"valid"`
	RedirectURL *string `json:"redirectUrl"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Badger struct {
	next                      http.Handler
	name                      string
	apiBaseUrl                string
	sessionQueryParameter     string
	userSessionCookieName     string
	resourceSessionCookieName string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:                      next,
		name:                      name,
		apiBaseUrl:                config.APIBaseUrl,
		sessionQueryParameter:     config.SessionQueryParameter,
		userSessionCookieName:     config.UserSessionCookieName,
		resourceSessionCookieName: config.ResourceSessionCookieName,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("config values are: ", p.apiBaseUrl, p.resourceSessionCookieName, p.sessionQueryParameter, p.userSessionCookieName)

	sess := req.URL.Query().Get(p.sessionQueryParameter)
	if sess != "" {
		http.SetCookie(rw, &http.Cookie{
			Name:   p.resourceSessionCookieName,
			Value:  sess,
			Path:   "/",
			Domain: req.Host,
		})

		query := req.URL.Query()
		query.Del(p.sessionQueryParameter)
		req.URL.RawQuery = query.Encode()
	}

	fmt.Println("checked for session param")

	cookies := p.extractCookies(req)
	if sess != "" {
		cookies.Session = &sess
	}

	fmt.Println("extracted cookies")

	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)

	fmt.Println("verify url is", verifyURL)

	originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.RequestURI())

	cookieData := VerifyBody{
		Sessions: SessionData{
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

	fmt.Println("built verify body")

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError) // TODO: redirect to error page
		return
	}

	fmt.Println("JSON data:", string(jsonData))

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	fmt.Println("response status code:", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("de marshalling response")

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("handling response")

	if result.RedirectURL != nil && *result.RedirectURL != "" {
		http.Redirect(rw, req, *result.RedirectURL, http.StatusFound)
		return
	}

	if !result.Valid { // only do this if for some reason the API doesn't return a redirect and it's not valid
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Println("serving authorized")

	p.next.ServeHTTP(rw, req)
}

func (p *Badger) extractCookies(req *http.Request) SessionData {
	var cookies SessionData

	if appSSOSessionCookie, err := req.Cookie(p.userSessionCookieName); err == nil {
		cookies.Session = &appSSOSessionCookie.Value
	}

	if resourceSessionCookie, err := req.Cookie(p.resourceSessionCookieName); err == nil {
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
