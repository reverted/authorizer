package authorizer

import (
	"errors"
	"net/http"
	"strings"
)

const (
	issKey = "iss"
	subKey = "sub"
	audKey = "aud"
	expKey = "exp"
)

var (
	ErrMissingAuthorizationHeader = errors.New("missing 'Authorization' header")
	ErrInvalidAuthorizationHeader = errors.New("invalid 'Authorization' header")
)

type opt func(*authorizer)

func WithNotary(notary Notary) opt {
	return func(a *authorizer) {
		a.Notary = notary
	}
}

func New(opts ...opt) *authorizer {
	auth := &authorizer{
		Notary: NewNotary(),
	}

	for _, opt := range opts {
		opt(auth)
	}

	return auth
}

type Notary interface {
	Notarize(string) (map[string]any, error)
}

type authorizer struct {
	Notary
}

func (a *authorizer) Authorize(r *http.Request) (map[string]any, error) {

	header := r.Header["Authorization"]
	if len(header) == 0 {
		return nil, ErrMissingAuthorizationHeader
	}

	parts := strings.Split(header[0], " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, ErrInvalidAuthorizationHeader
	}

	return a.Notary.Notarize(parts[1])
}

func NoopAuthorizer() *noopAuthorizer {
	return &noopAuthorizer{}
}

type noopAuthorizer struct{}

func (a *noopAuthorizer) Authorize(r *http.Request) (map[string]any, error) {
	return nil, nil
}
