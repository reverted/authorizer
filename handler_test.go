package authorizer_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

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
			authorizer.WithAuthorizedTokens("token", "eyJjbGFpbSI6InZhbHVlIn0K"),
			authorizer.WithAuthorizedClaim("key", "value"),
			authorizer.IncludeClaimInContext("key"),
			authorizer.IncludeClaimInContext("claim"),
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
				mockAuthorizer.EXPECT().Authorize(req).Return(nil, nil)
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
				mockAuthorizer.EXPECT().Authorize(req).Return(nil, nil)
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

		Context("when authorized token matches with claims", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "bearer eyJjbGFpbSI6InZhbHVlIn0K")
			})

			Context("it forwards the request to the handler", func() {
				BeforeEach(func() {
					mockHandler.EXPECT().ServeHTTP(rec, req)
				})

				It("succeeds", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusOK))
				})

				It("contains the correct claims", func() {
					Expect(req.Context().Value("claim")).To(Equal("value"))
				})
			})
		})

		Context("when the authorizer fails", func() {
			BeforeEach(func() {
				mockAuthorizer.EXPECT().Authorize(req).Return(nil, errors.New("nope"))
			})

			It("responds with Unauthorized", func() {
				Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("when the authorizer succeeds", func() {
			Context("when the authorized claims do not match", func() {
				BeforeEach(func() {
					mockAuthorizer.EXPECT().Authorize(req).Return(map[string]any{"not-key": "not-value"}, nil)
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the authorized claims match", func() {
				BeforeEach(func() {
					mockAuthorizer.EXPECT().Authorize(req).Return(map[string]any{"key": "value"}, nil)
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
					mockAuthorizer.EXPECT().Authorize(req).Return(nil, errors.New("nope"))
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the authorizer succeeds", func() {
				BeforeEach(func() {
					mockAuthorizer.EXPECT().Authorize(req).Return(nil, nil)
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

		Context("when a signing token is configured", func() {
			var body string

			BeforeEach(func() {
				body = `{"key":"value"}`

				handler = authorizer.NewHandler(
					newLogger(),
					mockHandler,
					authorizer.WithSigningTokens("secret"),
				)
			})

			Context("when the signature header is missing", func() {
				BeforeEach(func() {
					req, err = http.NewRequest("POST", "http://localhost", strings.NewReader(body))
					Expect(err).NotTo(HaveOccurred())
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the signature does not match", func() {
				BeforeEach(func() {
					req, err = http.NewRequest("POST", "http://localhost", strings.NewReader(body))
					Expect(err).NotTo(HaveOccurred())
					req.Header.Set("X-Signature", "invalidsignature")
				})

				It("responds with Unauthorized", func() {
					Expect(rec.Result().StatusCode).To(Equal(http.StatusUnauthorized))
				})
			})

			Context("when the signature matches", func() {
				BeforeEach(func() {
					mac := hmac.New(sha256.New, []byte("secret"))
					mac.Write([]byte(body))
					sig := hex.EncodeToString(mac.Sum(nil))

					req, err = http.NewRequest("POST", "http://localhost", bytes.NewBufferString(body))
					Expect(err).NotTo(HaveOccurred())
					req.Header.Set("X-Signature", sig)
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

func (l *logger) Error(args ...any) {
	fmt.Fprintln(GinkgoWriter, args...)
}
