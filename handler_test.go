package authorizer_test

import (
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/reverted/authorizer"
	"github.com/reverted/logger"
)

var _ = Describe("Handler", func() {

	var (
		err error
		req *http.Request
		rec *httptest.ResponseRecorder

		fakeAuthorizer *FakeAuthorizer
		fakeRouter     *FakeRouter
		fakeHandler    *FakeHandler

		handler http.Handler
	)

	BeforeEach(func() {
		fakeAuthorizer = new(FakeAuthorizer)
		fakeRouter = new(FakeRouter)
		fakeHandler = new(FakeHandler)

		handler = authorizer.NewHandler(
			logger.New("test",
				logger.Writer(GinkgoWriter),
				logger.Level(logger.Debug),
			),
			fakeAuthorizer,
			fakeRouter,
			fakeHandler,
		)
	})

	Describe("ServeHTTP", func() {
		BeforeEach(func() {
			req, err = http.NewRequest("GET", "http://localhost", nil)
			Expect(err).NotTo(HaveOccurred())

			rec = httptest.NewRecorder()
		})

		JustBeforeEach(func() {
			handler.ServeHTTP(rec, req)
		})

		Context("when the authorizer fails", func() {
			BeforeEach(func() {
				fakeAuthorizer.AuthorizeReturns(errors.New("nope"))
			})

			It("responds with Unauthorized", func() {
				Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("when the authorizer succeeds", func() {
			BeforeEach(func() {
				fakeAuthorizer.AuthorizeReturns(nil)
			})

			Context("when the router fails", func() {
				BeforeEach(func() {
					fakeRouter.RouteReturns(errors.New("nope"))
				})

				It("responds with Not Found", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusNotFound))
				})
			})

			Context("when the router succeeds", func() {
				BeforeEach(func() {
					fakeRouter.RouteReturns(nil)
				})

				It("forwards the request to the handler", func() {
					recArg, reqArg := fakeHandler.ServeHTTPCallArgs()
					Expect(recArg).To(Equal(rec))
					Expect(reqArg).To(Equal(req))
				})
			})
		})
	})
})

type FakeAuthorizer struct {
	request *http.Request
	err     error
}

func (self *FakeAuthorizer) Authorize(r *http.Request) error {
	self.request = r
	return self.err
}

func (self *FakeAuthorizer) AuthorizeReturns(err error) {
	self.err = err
}

func (self *FakeAuthorizer) AuthorizeCallArgs() *http.Request {
	return self.request
}

type FakeRouter struct {
	request *http.Request
	err     error
}

func (self *FakeRouter) Route(r *http.Request) error {
	self.request = r
	return self.err
}

func (self *FakeRouter) RouteReturns(err error) {
	self.err = err
}

func (self *FakeRouter) RouteCallArgs() *http.Request {
	return self.request
}

type FakeHandler struct {
	request *http.Request
	writer  http.ResponseWriter
}

func (self *FakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.writer = w
	self.request = r
}

func (self *FakeHandler) ServeHTTPCallArgs() (http.ResponseWriter, *http.Request) {
	return self.writer, self.request
}
