package authorizer_test

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/reverted/authorizer"
	"github.com/reverted/logger"
)

type Router interface {
	Route(r *http.Request) error
}

var _ = Describe("Router", func() {

	var (
		err    error
		router Router
	)

	BeforeEach(func() {
		router = authorizer.NewRouter(
			logger.New("test",
				logger.Writer(GinkgoWriter),
				logger.Level(logger.Debug),
			),
			authorizer.Routes(
				authorizer.Route("some-resource", authorizer.Methods("some-method")),
			),
			authorizer.Unrestricted("user_id_key", "some-sub"),
		)
	})

	Describe("Route", func() {
		var ctx context.Context
		var req *http.Request

		BeforeEach(func() {
			req, err = http.NewRequest("some-method", "http://some.url", nil)
			Expect(err).NotTo(HaveOccurred())

			ctx = context.Background()
		})

		JustBeforeEach(func() {
			err = router.Route(req)
		})

		Context("when the 'sub' has full access", func() {
			BeforeEach(func() {
				ctx = context.WithValue(ctx, "user_id_key", "some-sub")
				req = req.WithContext(ctx)
			})

			It("succeeds", func() {
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when the 'sub' does not have full access", func() {
			BeforeEach(func() {
				ctx = context.WithValue(ctx, "user_id_key", "some-other-sub")
				req = req.WithContext(ctx)
			})

			Context("when the path does not exist", func() {
				BeforeEach(func() {
					req.URL.Path = "some-other-resource"
				})

				It("errors", func() {
					Expect(err).To(HaveOccurred())
				})
			})

			Context("when the path exists", func() {
				BeforeEach(func() {
					req.URL.Path = "some-resource"
				})

				Context("when the method does not exist", func() {
					BeforeEach(func() {
						req.Method = "some-non-existant-method"
					})

					It("errors", func() {
						Expect(err).To(HaveOccurred())
					})
				})

				Context("when the method exists", func() {
					BeforeEach(func() {
						req.Method = "some-method"
					})

					It("succeeds", func() {
						Expect(err).NotTo(HaveOccurred())
					})
				})
			})
		})
	})
})
