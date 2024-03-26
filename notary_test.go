package authorizer_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/onsi/gomega/ghttp"
	"github.com/reverted/authorizer"
)

type Notary interface {
	Notarize(token string) (map[string]interface{}, error)
}

var _ = Describe("Notary", func() {
	var (
		notary Notary
		server *ghttp.Server

		err error
		res map[string]interface{}

		privateKey    *rsa.PrivateKey
		jsonWebKeySet jose.JSONWebKeySet
		claims        jwt.Claims
	)

	BeforeEach(func() {
		server = ghttp.NewServer()

		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		jsonWebKeySet = jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				KeyID:     "some-key",
				Use:       "sig",
				Algorithm: string(jose.RS256),
				Key:       &privateKey.PublicKey,
			}},
		}

		claims = jwt.Claims{
			Subject:  "subject",
			Issuer:   "issuer",
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute)),
			Audience: jwt.Audience{"audience"},
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("Notarize", func() {

		JustBeforeEach(func() {
			var signer jose.Signer
			signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}
			signer, err = jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "some-key"))
			Expect(err).NotTo(HaveOccurred())

			var token string
			token, err = jwt.Signed(signer).Claims(claims).Serialize()
			Expect(err).NotTo(HaveOccurred())

			res, err = notary.Notarize(token)
		})

		BeforeEach(func() {
			notary = authorizer.NewNotary(
				authorizer.WithAudience("audience"),
				authorizer.WithTarget(server.URL()+"/token_keys"),
			)
		})

		Context("when it fails to fetch the public key", func() {
			BeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/token_keys"),
						ghttp.RespondWith(http.StatusInternalServerError, nil),
					),
				)
			})

			It("errors", func() {
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when it successfully fetches the public key", func() {
			BeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/token_keys"),
						ghttp.RespondWithJSONEncoded(http.StatusOK, jsonWebKeySet),
					),
				)
			})

			It("validates the token", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(res["sub"]).To(Equal("subject"))
				Expect(res["iss"]).To(Equal("issuer"))
				Expect(res["aud"]).To(Equal("audience"))
			})
		})
	})
})
