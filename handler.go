package authorizer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

type Logger interface {
	Error(a ...any)
}

type Authorizer interface {
	Authorize(r *http.Request) error
}

type handlerOpt func(h *handler)

func WithAuthorizer(authorizer Authorizer) handlerOpt {
	return func(h *handler) {
		h.Authorizer = authorizer
	}
}

func WithBasicAuthCredential(user, pass string) handlerOpt {
	return func(h *handler) {
		h.BasicAuthCredentials = append(h.BasicAuthCredentials, BasicAuthCredential{user, pass})
	}
}

func WithAuthorizedTokens(values ...string) handlerOpt {
	return func(h *handler) {
		for _, value := range values {
			h.AuthorizedTokens = append(h.AuthorizedTokens, AuthorizedToken{value})
		}
	}
}

func WithAuthorizedClaim(key string, value any) handlerOpt {
	return func(h *handler) {
		h.AuthorizedClaims = append(h.AuthorizedClaims, AuthorizedClaim{key, value})
	}
}

func WithAuthorizedClaims(values ...AuthorizedClaim) handlerOpt {
	return func(h *handler) {
		h.AuthorizedClaims = append(h.AuthorizedClaims, values...)
	}
}

func WithAuthorizedSubjects(values ...string) handlerOpt {
	return func(h *handler) {
		for _, value := range values {
			h.AuthorizedClaims = append(h.AuthorizedClaims, AuthorizedClaim{"sub", value})
		}
	}
}

func WithApiKeys(values ...string) handlerOpt {
	return func(h *handler) {
		for _, value := range values {
			h.ApiKeys = append(h.ApiKeys, ApiKey{value})
		}
	}
}

func NewHandler(
	logger Logger,
	next http.Handler,
	opts ...handlerOpt,
) *handler {
	handler := &handler{
		Logger:     logger,
		Authorizer: NoopAuthorizer(),
		Handler:    next,
	}

	for _, opt := range opts {
		opt(handler)
	}

	return handler
}

type handler struct {
	Logger
	Authorizer
	http.Handler

	BasicAuthCredentials []BasicAuthCredential
	AuthorizedTokens     []AuthorizedToken
	AuthorizedClaims     []AuthorizedClaim
	ApiKeys              []ApiKey
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if len(h.ApiKeys) == 0 {
		h.Serve(w, r)
		return
	}

	for _, key := range h.ApiKeys {
		if key.Matches(r) {
			h.Serve(w, r)
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func (h *handler) Serve(w http.ResponseWriter, r *http.Request) {

	for _, cred := range h.BasicAuthCredentials {
		if cred.Matches(r) {
			h.Handler.ServeHTTP(w, r)
			return
		}
	}

	for _, token := range h.AuthorizedTokens {
		if token.Matches(r) {
			h.Handler.ServeHTTP(w, r)
			return
		}
	}

	if err := h.Authorizer.Authorize(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		h.Logger.Error(err)
		return
	}

	for _, claim := range h.AuthorizedClaims {
		if claim.Matches(r) {
			h.Handler.ServeHTTP(w, r)
			return
		}
	}

	hasCreds := len(h.BasicAuthCredentials) > 0
	hasTokens := len(h.AuthorizedTokens) > 0
	hasClaims := len(h.AuthorizedClaims) > 0

	if hasCreds || hasTokens || hasClaims {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	h.Handler.ServeHTTP(w, r)
}

type BasicAuthCredential struct {
	Username, Password string
}

func (c BasicAuthCredential) Matches(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && c.Username == user && c.Password == pass
}

type AuthorizedToken struct {
	Value string
}

func (t AuthorizedToken) Matches(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if header == "" {
		return false
	}

	parts := strings.Split(header, " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}

	if parts[1] != t.Value {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}

	var data map[string]any
	if err = json.Unmarshal(decoded, &data); err != nil {
		return true
	}

	ctx := r.Context()

	for claim, value := range data {
		ctx = context.WithValue(ctx, claim, value)
	}

	*r = *r.WithContext(ctx)

	return true
}

type AuthorizedClaim struct {
	Key   string
	Value any
}

func (c AuthorizedClaim) Matches(r *http.Request) bool {
	return r.Context().Value(c.Key) == c.Value
}

type ApiKey struct {
	Value string
}

func (k ApiKey) Matches(r *http.Request) bool {
	header := r.Header.Get("X-Api-Key")
	if header == "" {
		return false
	}

	return header == k.Value
}
