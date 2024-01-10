package authorizer

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

var (
	ErrNoPublicKey      = errors.New("No public key")
	ErrInvalidToken     = errors.New("Invalid token")
	ErrInvalidSignature = errors.New("Invalid signature")
	ErrTokenExpired     = errors.New("Token expired")
	ErrInvalidAudience  = errors.New("Invalid audience")
	ErrNoTargetSet      = errors.New("No target set")
	ErrNoKeysFound      = errors.New("No keys found")
)

type notaryOpt func(*notary)

func WithTarget(target string) notaryOpt {
	return func(self *notary) {
		var err error
		if self.URL, err = url.Parse(target); err != nil {
			log.Fatal(err)
		}
	}
}

func WithHttpClient(client *http.Client) notaryOpt {
	return func(self *notary) {
		self.Client = client
	}
}

func WithAudience(auds ...string) notaryOpt {
	return func(self *notary) {
		self.Audience = auds
	}
}

func NewNotary(opts ...notaryOpt) *notary {
	notary := &notary{}

	for _, opt := range opts {
		opt(notary)
	}

	if notary.Client == nil {
		WithHttpClient(http.DefaultClient)(notary)
	}

	return notary
}

type notary struct {
	sync.Mutex
	*url.URL
	*http.Client
	*jose.JSONWebKeySet
	Audience []string
}

func (self *notary) Notarize(token string) (map[string]interface{}, error) {

	raw, err := self.notarize(token)

	switch err {
	case ErrNoPublicKey, ErrInvalidSignature:
		if err = self.refreshKeySet(); err != nil {
			return nil, err
		}
		return self.notarize(token)
	default:
		return raw, err
	}
}

func (self *notary) notarize(token string) (map[string]interface{}, error) {

	if self.JSONWebKeySet == nil {
		return nil, ErrNoPublicKey
	}

	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims jwt.Claims
	var raw map[string]interface{}

	if err = parsed.Claims(self.JSONWebKeySet, &claims, &raw); err != nil {
		return nil, ErrInvalidSignature
	}

	if err = claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, ErrTokenExpired
	}

	for _, aud := range self.Audience {
		if claims.Audience.Contains(aud) {
			return raw, nil
		}
	}

	return nil, ErrInvalidAudience
}

func (self *notary) refreshKeySet() error {
	self.Lock()
	defer self.Unlock()

	keySet, err := self.fetchKeySet()
	if err != nil {
		return err
	}

	self.JSONWebKeySet = keySet
	return nil
}

func (self *notary) fetchKeySet() (*jose.JSONWebKeySet, error) {

	if self.URL == nil {
		return nil, ErrNoTargetSet
	}

	resp, err := self.Client.Get(self.URL.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Failed to fetch public key: " + resp.Status)
	}

	var data jose.JSONWebKeySet
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if len(data.Keys) == 0 {
		return nil, ErrNoKeysFound
	}

	return &data, nil
}
