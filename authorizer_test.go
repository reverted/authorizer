package authorizer_test

import (
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/reverted/authorizer"
)

type Authorizer interface {
	Authorize(r *http.Request) error
}

var _ = Describe("Authorizer", func() {

	var (
		err        error
		req        *http.Request
		authz      Authorizer
		fakeNotary *FakeNotary
	)

	BeforeEach(func() {
		fakeNotary = new(FakeNotary)

		authz = authorizer.New(
			authorizer.WithNotary(fakeNotary),
		)
	})

	Describe("Authorize", func() {
		BeforeEach(func() {
			req, err = http.NewRequest("GET", "http://localhost", nil)
			Expect(err).NotTo(HaveOccurred())
		})

		JustBeforeEach(func() {
			err = authz.Authorize(req)
		})

		Context("when the authorization header is missing", func() {
			BeforeEach(func() {
				req.Header.Del("Authorization")
			})

			It("errors", func() {
				Expect(err).To(Equal(authorizer.ErrMissingAuthorizationHeader))
			})
		})

		Context("when the authorization header is malformed", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "blah")
			})

			It("errors", func() {
				Expect(err).To(Equal(authorizer.ErrInvalidAuthorizationHeader))
			})
		})

		Context("when the authorization header is not a bearer token", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "not-bearer token")
			})

			It("errors", func() {
				Expect(err).To(Equal(authorizer.ErrInvalidAuthorizationHeader))
			})
		})

		Context("when the bearer token is valid", func() {
			BeforeEach(func() {
				req.Header.Set("Authorization", "bearer token")
			})

			It("invokes the notary with the token", func() {
				Expect(fakeNotary.NotarizeCallArgs()).To(Equal("token"))
			})

			Context("when the notary fails to verify the signature", func() {
				BeforeEach(func() {
					fakeNotary.NotarizeReturns(nil, errors.New("nope"))
				})

				It("errors", func() {
					Expect(err).To(HaveOccurred())
				})
			})

			Context("when the notary succcessfully verifies the signature", func() {
				BeforeEach(func() {
					fakeNotary.NotarizeReturns(map[string]interface{}{}, nil)
				})

				It("succeeds", func() {
					Expect(err).NotTo(HaveOccurred())
				})
			})

			Context("when configured to include the subject", func() {
				BeforeEach(func() {
					authz = authorizer.New(
						authorizer.WithNotary(fakeNotary),
						authorizer.IncludeSubjectAs("some-key"),
					)

					fakeNotary.NotarizeReturns(map[string]interface{}{
						"sub": "some-value",
					}, nil)
				})

				It("updates the context with the subject", func() {
					value := req.Context().Value("some-key")
					Expect(value).To(Equal("some-value"))
				})
			})
		})
	})
})

type FakeNotary struct {
	token string
	data  map[string]interface{}
	err   error
}

func (self *FakeNotary) Notarize(token string) (map[string]interface{}, error) {
	self.token = token
	return self.data, self.err
}

func (self *FakeNotary) NotarizeReturns(data map[string]interface{}, err error) {
	self.data = data
	self.err = err
}

func (self *FakeNotary) NotarizeCallArgs() string {
	return self.token
}
