package authorizer

import (
	"net/http"
)

type Logger interface {
	Error(a ...interface{})
}

type Authorizer interface {
	Authorize(r *http.Request) error
}

func NewHandler(
	logger Logger,
	authorizer Authorizer,
	next http.Handler,
) *handler {
	return &handler{
		logger,
		authorizer,
		next,
	}
}

type handler struct {
	Logger
	Authorizer
	http.Handler
}

func (self *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if err := self.Authorizer.Authorize(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		self.Logger.Error(err)
		return
	}

	self.Handler.ServeHTTP(w, r)
}
