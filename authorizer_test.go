package authorizer_test

import (
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"
	"github.com/reverted/authorizer"
	"github.com/reverted/authorizer/mocks"
)

type Authorizer interface {
	Authorize(r *http.Request) (map[string]any, error)
}

var _ = Describe("Authorizer", func() {

	var (
		err   error
		req   *http.Request
		authz Authorizer
		res   map[string]any

		mockCtrl   *gomock.Controller
		mockNotary *mocks.MockNotary
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockNotary = mocks.NewMockNotary(mockCtrl)

		authz = authorizer.New(
			authorizer.WithNotary(mockNotary),
		)
	})

	Describe("Authorize", func() {
		BeforeEach(func() {
			req, err = http.NewRequest("GET", "http://localhost", nil)
			Expect(err).NotTo(HaveOccurred())
		})

		JustBeforeEach(func() {
			res, err = authz.Authorize(req)
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

			Context("when the notary fails to verify the signature", func() {
				BeforeEach(func() {
					mockNotary.EXPECT().Notarize("token").Return(nil, errors.New("nope"))
				})

				It("errors", func() {
					Expect(err).To(HaveOccurred())
				})
			})

			Context("when the notary succcessfully verifies the signature", func() {
				BeforeEach(func() {
					mockNotary.EXPECT().Notarize("token").Return(map[string]any{}, nil)
				})

				It("succeeds", func() {
					Expect(len(res)).To(Equal(0))
					Expect(err).NotTo(HaveOccurred())
				})
			})

			Context("when configured to include the subject", func() {
				BeforeEach(func() {
					mockNotary.EXPECT().Notarize("token").Return(map[string]any{
						"sub": "some-value",
					}, nil)
				})

				It("updates the context with the subject", func() {
					Expect(len(res)).To(Equal(1))
					Expect(res["sub"]).To(Equal("some-value"))
				})
			})
		})
	})
})
