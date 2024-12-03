package authorizer

import (
	"context"
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
	ErrMissingAuthorizationHeader = errors.New("Missing 'Authorization' header")
	ErrInvalidAuthorizationHeader = errors.New("Invalid 'Authorization' header")
)

type opt func(*authorizer)

func WithNotary(notary Notary) opt {
	return func(a *authorizer) {
		a.Notary = notary
	}
}

func IncludeIssuer() opt {
	return IncludeClaimAs(issKey, issKey)
}

func IncludeIssuerAs(key string) opt {
	return IncludeClaimAs(issKey, key)
}

func IncludeSubject() opt {
	return IncludeClaimAs(subKey, subKey)
}

func IncludeSubjectAs(key string) opt {
	return IncludeClaimAs(subKey, key)
}

func IncludeAudience() opt {
	return IncludeClaimAs(audKey, audKey)
}

func IncludeAudienceAs(key string) opt {
	return IncludeClaimAs(audKey, key)
}

func IncludeExpiration() opt {
	return IncludeClaimAs(expKey, expKey)
}

func IncludeExpirationAs(key string) opt {
	return IncludeClaimAs(expKey, key)
}

func IncludeClaim(key string) opt {
	return IncludeClaimAs(key, key)
}

func IncludeClaims(pairs ...string) opt {
	return func(a *authorizer) {
		for _, pair := range pairs {
			if parts := strings.Split(pair, ":"); len(parts) == 2 {
				IncludeClaimAs(parts[0], parts[1])(a)
			}
		}
	}
}

func IncludeClaimAs(from string, to string) opt {
	return func(a *authorizer) {
		if from != "" && to != "" {
			a.ClaimMapping[from] = to
		}
	}
}

func New(opts ...opt) *authorizer {
	auth := &authorizer{
		Notary:       NewNotary(),
		ClaimMapping: map[string]string{},
	}

	for _, opt := range opts {
		opt(auth)
	}

	return auth
}

type Notary interface {
	Notarize(string) (map[string]interface{}, error)
}

type authorizer struct {
	Notary
	ClaimMapping map[string]string
}

func (a *authorizer) Authorize(r *http.Request) error {

	header := r.Header["Authorization"]
	if len(header) == 0 {
		return ErrMissingAuthorizationHeader
	}

	parts := strings.Split(header[0], " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ErrInvalidAuthorizationHeader
	}

	data, err := a.Notary.Notarize(parts[1])
	if err != nil {
		return err
	}

	return a.updateContext(r, data)
}

func (a *authorizer) updateContext(r *http.Request, data map[string]interface{}) error {

	ctx := r.Context()

	for claim, key := range a.ClaimMapping {
		ctx = context.WithValue(ctx, key, data[claim])
	}

	*r = *r.WithContext(ctx)

	return nil
}

func NoopAuthorizer() *noopAuthorizer {
	return &noopAuthorizer{}
}

type noopAuthorizer struct{}

func (a *noopAuthorizer) Authorize(r *http.Request) error {
	return nil
}
