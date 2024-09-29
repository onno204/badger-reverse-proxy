package badger

import (
	"context"
	"net/http"
	"time"
)

type Config struct {
	APIAddress string `json:"apiAddress"`
	ValidToken string `json:"validToken"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Badger struct {
	next       http.Handler
	name       string
	apiAdress  string
	validToken string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:       next,
		name:       name,
		apiAdress:  config.APIAddress,
		validToken: config.ValidToken,
	}, nil
}

// THIS IS AN EAXMPLE FOR TESTING

var usedTokens = make(map[string]bool)

const cookieName = "access_token"
const cookieDuration = 1 * time.Minute

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if _, err := req.Cookie(cookieName); err == nil {
		p.next.ServeHTTP(rw, req)
		return
	}

	queryToken := req.URL.Query().Get("token")
	if queryToken == "" {
		http.Error(rw, "Missing token", http.StatusUnauthorized)
		return
	}

	if queryToken != p.validToken || usedTokens[queryToken] {
		http.Error(rw, "Invalid or already used token", http.StatusUnauthorized)
		return
	}

	usedTokens[queryToken] = true

	expiration := time.Now().Add(cookieDuration)
	http.SetCookie(rw, &http.Cookie{
		Name:    cookieName,
		Value:   "temporary-access",
		Expires: expiration,
		Path:    "/",
	})

	p.next.ServeHTTP(rw, req)
}
