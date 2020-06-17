package authorizer_test

import (
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"
	"github.com/reverted/authorizer"
	"github.com/reverted/authorizer/mocks"
	"github.com/reverted/logger"
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
			logger.New("test",
				logger.Writer(GinkgoWriter),
				logger.Level(logger.Debug),
			),
			mockAuthorizer,
			mockHandler,
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

			Context("when it forwards the request to the handler", func() {
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
