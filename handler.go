package authorizer

import (
	"net/http"
	"strings"
)

type Logger interface {
	Error(a ...interface{})
}

type Authorizer interface {
	Authorize(r *http.Request) error
}

type handlerOpt func(self *handler)

func WithBasicAuthCredential(user, pass string) handlerOpt {
	return func(self *handler) {
		self.BasicAuthCredentials = append(self.BasicAuthCredentials, BasicAuthCredential{user, pass})
	}
}

func WithAuthorizedToken(value string) handlerOpt {
	return func(self *handler) {
		self.AuthorizedTokens = append(self.AuthorizedTokens, AuthorizedToken{value})
	}
}

func WithAuthorizedClaim(key, value string) handlerOpt {
	return func(self *handler) {
		self.AuthorizedClaims = append(self.AuthorizedClaims, AuthorizedClaim{key, value})
	}
}

func NewHandler(
	logger Logger,
	authorizer Authorizer,
	next http.Handler,
	opts ...handlerOpt,
) *handler {
	handler := &handler{
		Logger:     logger,
		Authorizer: authorizer,
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
}

func (self *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	for _, cred := range self.BasicAuthCredentials {
		if cred.Matches(r) {
			self.Handler.ServeHTTP(w, r)
			return
		}
	}

	for _, claim := range self.AuthorizedTokens {
		if claim.Matches(r) {
			self.Handler.ServeHTTP(w, r)
			return
		}
	}

	if err := self.Authorizer.Authorize(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		self.Logger.Error(err)
		return
	}

	for _, claim := range self.AuthorizedClaims {
		if claim.Matches(r) {
			self.Handler.ServeHTTP(w, r)
			return
		}
	}

	hasCreds := len(self.BasicAuthCredentials) > 0
	hasTokens := len(self.AuthorizedTokens) > 0
	hasClaims := len(self.AuthorizedClaims) > 0

	if hasCreds || hasTokens || hasClaims {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	self.Handler.ServeHTTP(w, r)
}

type BasicAuthCredential struct {
	Username, Password string
}

func (self BasicAuthCredential) Matches(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && self.Username == user && self.Password == pass
}

type AuthorizedToken struct {
	Value string
}

func (self AuthorizedToken) Matches(r *http.Request) bool {
	header := r.Header["Authorization"]
	if len(header) == 0 {
		return false
	}

	parts := strings.Split(header[0], " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}

	return parts[1] == self.Value
}

type AuthorizedClaim struct {
	Key, Value string
}

func (self AuthorizedClaim) Matches(r *http.Request) bool {
	return r.Context().Value(self.Key) == self.Value
}
