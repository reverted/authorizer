package authorizer_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"
	"github.com/reverted/authorizer"
	"github.com/reverted/authorizer/mocks"
)

var _ = Describe("Handler", func() {

	var (
		err error
		req *http.Request
		rec *httptest.ResponseRecorder

		mockCtrl       *gomock.Controller
		mockAuthorizer *mocks.MockAuthorizer
		mockHandler    *mocks.MockHandler

		handler http.Handler
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockAuthorizer = mocks.NewMockAuthorizer(mockCtrl)
		mockHandler = mocks.NewMockHandler(mockCtrl)

		handler = authorizer.NewHandler(
			newLogger(),
			mockHandler,
			authorizer.WithAuthorizer(mockAuthorizer),
			authorizer.WithBasicAuthCredential("user", "pass"),
			authorizer.WithAuthorizedTokens("token"),
			authorizer.WithAuthorizedClaim("key", "value"),
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

		Context("when basic auth credentials do not match", func() {
			BeforeEach(func() {
				req.SetBasicAuth("not-user", "not-pass")
				mockAuthorizer.EXPECT().Authorize(req).Return(nil)
			})

			It("responds with Unauthorized", func() {
				Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("when basic auth credentials match", func() {
			BeforeEach(func() {
				req.SetBasicAuth("user", "pass")
			})

			Context("it forwards the request to the handler", func() {
				BeforeEach(func() {
					mockHandler.EXPECT().ServeHTTP(rec, req)
				})

				It("succeeds", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusOK))
				})
			})
		})

		Context("when authorized token does not match", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "bearer not-token")
				mockAuthorizer.EXPECT().Authorize(req).Return(nil)
			})

			It("responds with Unauthorized", func() {
				Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("when authorized token matches", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "bearer token")
			})

			Context("it forwards the request to the handler", func() {
				BeforeEach(func() {
					mockHandler.EXPECT().ServeHTTP(rec, req)
				})

				It("succeeds", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusOK))
				})
			})
		})

		Context("when the authorizer fails", func() {
			BeforeEach(func() {
				mockAuthorizer.EXPECT().Authorize(req).Return(errors.New("nope"))
			})

			It("responds with Unauthorized", func() {
				Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("when the authorizer succeeds", func() {
			BeforeEach(func() {
				mockAuthorizer.EXPECT().Authorize(req).Return(nil)
			})

			Context("when the authorized claims do not match", func() {
				BeforeEach(func() {
					ctx := context.WithValue(context.Background(), "not-key", "not-value")
					*req = *req.WithContext(ctx)
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the authorized claims match", func() {
				BeforeEach(func() {
					ctx := context.WithValue(context.Background(), "key", "value")
					*req = *req.WithContext(ctx)
				})

				Context("it forwards the request to the handler", func() {
					BeforeEach(func() {
						mockHandler.EXPECT().ServeHTTP(rec, req)
					})

					It("succeeds", func() {
						Expect(rec.Result().StatusCode).To(Equal(http.StatusOK))
					})
				})
			})
		})

		Context("when no creds or claims or tokens are provided", func() {
			BeforeEach(func() {
				handler = authorizer.NewHandler(
					newLogger(),
					mockHandler,
					authorizer.WithAuthorizer(mockAuthorizer),
				)
			})

			Context("when the authorizer fails", func() {
				BeforeEach(func() {
					mockAuthorizer.EXPECT().Authorize(req).Return(errors.New("nope"))
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the authorizer succeeds", func() {
				BeforeEach(func() {
					mockAuthorizer.EXPECT().Authorize(req).Return(nil)
				})

				Context("it forwards the request to the handler", func() {
					BeforeEach(func() {
						mockHandler.EXPECT().ServeHTTP(rec, req)
					})

					It("succeeds", func() {
						Expect(rec.Result().StatusCode).To(Equal(http.StatusOK))
					})
				})
			})
		})
	})
})

func newLogger() *logger {
	return &logger{}
}

type logger struct{}

func (l *logger) Error(args ...interface{}) {
	fmt.Fprintln(GinkgoWriter, args...)
}
