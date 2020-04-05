package authorizer

import (
	"errors"
	"net/http"
)

type accessOpt func(*access)
type routeOpt func(*route)
type routerOpt func(*router)

func Unrestricted(key, value string) routerOpt {
	return func(self *router) {
		access := access{key, value}
		self.Unrestricted = append(self.Unrestricted, access)
	}
}

func Routes(routes ...route) routerOpt {
	return func(self *router) {
		for _, route := range routes {
			self.Routes[route.Resource] = route
		}
	}
}

func Route(resource string, opts ...routeOpt) route {
	route := route{resource, map[string]bool{}}
	for _, opt := range opts {
		opt(&route)
	}
	return route
}

func Methods(methods ...string) routeOpt {
	return func(self *route) {
		for _, method := range methods {
			self.Methods[method] = true
		}
	}
}

func Read(resource string) route {
	return Route(resource, Methods("GET"))
}

func Write(resource string) route {
	return Route(resource, Methods("POST", "PUT", "DELETE"))
}

func Get(resource string) route {
	return Route(resource, Methods("GET"))
}

func Put(resource string) route {
	return Route(resource, Methods("PUT"))
}

func Post(resource string) route {
	return Route(resource, Methods("POST"))
}

func Delete(resource string) route {
	return Route(resource, Methods("DELETE"))
}

func NewRouter(logger Logger, opts ...routerOpt) *router {
	router := &router{
		Logger:       logger,
		Routes:       map[string]route{},
		Unrestricted: []access{},
	}

	for _, opt := range opts {
		opt(router)
	}

	return router
}

type router struct {
	Logger
	Routes       map[string]route
	Unrestricted []access
}

type route struct {
	Resource string
	Methods  map[string]bool
}

type access struct {
	Key   string
	Value string
}

func (self *router) Route(r *http.Request) error {

	for _, access := range self.Unrestricted {
		val := r.Context().Value(access.Key)

		if v, _ := val.(string); v == access.Value {
			return nil
		}
	}

	route, ok := self.Routes[r.URL.Path]
	if !ok {
		return errors.New("No route")
	}

	if !route.Methods[r.Method] {
		return errors.New("No method for route")
	}

	return nil
}
