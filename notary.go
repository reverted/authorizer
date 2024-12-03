package authorizer

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	ErrNoPublicKey      = errors.New("no public key")
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidAudience  = errors.New("invalid audience")
	ErrNoTargetSet      = errors.New("no target set")
	ErrNoKeysFound      = errors.New("no keys found")
)

type notaryOpt func(*notary)

func WithTarget(target string) notaryOpt {
	return func(n *notary) {
		var err error
		if n.URL, err = url.Parse(target); err != nil {
			log.Fatal(err)
		}
	}
}

func WithHttpClient(client *http.Client) notaryOpt {
	return func(n *notary) {
		n.Client = client
	}
}

func WithAudience(auds ...string) notaryOpt {
	return func(n *notary) {
		n.Audience = auds
	}
}

func WithSignatureAlgorithm(alg string) notaryOpt {
	return func(n *notary) {
		n.Algorithms = append(n.Algorithms, jose.SignatureAlgorithm(alg))

	}
}

func NewNotary(opts ...notaryOpt) *notary {
	notary := &notary{
		Algorithms: []jose.SignatureAlgorithm{jose.RS256},
	}

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
	Audience   []string
	Algorithms []jose.SignatureAlgorithm
}

func (n *notary) Notarize(token string) (map[string]interface{}, error) {

	raw, err := n.notarize(token)

	switch err {
	case ErrNoPublicKey, ErrInvalidSignature:
		if err = n.refreshKeySet(); err != nil {
			return nil, err
		}
		return n.notarize(token)
	default:
		return raw, err
	}
}

func (n *notary) notarize(token string) (map[string]interface{}, error) {

	if n.JSONWebKeySet == nil {
		return nil, ErrNoPublicKey
	}

	parsed, err := jwt.ParseSigned(token, n.Algorithms)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims jwt.Claims
	var raw map[string]interface{}

	if err = parsed.Claims(n.JSONWebKeySet, &claims, &raw); err != nil {
		return nil, ErrInvalidSignature
	}

	if err = claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, ErrTokenExpired
	}

	for _, aud := range n.Audience {
		if claims.Audience.Contains(aud) {
			return raw, nil
		}
	}

	return nil, ErrInvalidAudience
}

func (n *notary) refreshKeySet() error {
	n.Lock()
	defer n.Unlock()

	keySet, err := n.fetchKeySet()
	if err != nil {
		return err
	}

	n.JSONWebKeySet = keySet
	return nil
}

func (n *notary) fetchKeySet() (*jose.JSONWebKeySet, error) {

	if n.URL == nil {
		return nil, ErrNoTargetSet
	}

	resp, err := n.Client.Get(n.URL.String())
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
