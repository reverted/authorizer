package authorizer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

func WithPublicKey(key *rsa.PublicKey) notaryOpt {
	return func(self *notary) {
		self.PublicKey = key
	}
}

func WithPublicKeyContents(value string) notaryOpt {
	return func(self *notary) {
		block, _ := pem.Decode([]byte(value))

		if block == nil {
			log.Fatal(errors.New("Invalid public key: " + value))
		}

		if block.Type != "PUBLIC KEY" {
			log.Fatal(errors.New("Invalid block type: " + block.Type))
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			log.Fatal(errors.New("Invalid public key type"))
		}

		self.PublicKey = publicKey
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
	*rsa.PublicKey
	Audience []string
}

func (self *notary) Notarize(token string) (map[string]interface{}, error) {

	raw, err := self.notarize(token)

	switch err {
	case ErrNoPublicKey, ErrInvalidSignature:
		if err = self.refreshPublicKey(); err != nil {
			return nil, err
		}
		return self.notarize(token)
	default:
		return raw, err
	}
}

func (self *notary) notarize(token string) (map[string]interface{}, error) {

	if self.PublicKey == nil {
		return nil, ErrNoPublicKey
	}

	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims jwt.Claims
	var raw map[string]interface{}

	if err = parsed.Claims(self.PublicKey, &claims, &raw); err != nil {
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

func (self *notary) refreshPublicKey() error {
	self.Lock()
	defer self.Unlock()

	publicKey, err := self.fetchPublicKey()
	if err != nil {
		return err
	}

	self.PublicKey = publicKey
	return nil
}

func (self *notary) fetchPublicKey() (*rsa.PublicKey, error) {

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

	return data.Keys[0].Public().Key.(*rsa.PublicKey), nil
}
