package authorizer_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/ghttp"
	"github.com/reverted/authorizer"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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
			signer, err = jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
			Expect(err).NotTo(HaveOccurred())

			var token string
			token, err = jwt.Signed(signer).Claims(claims).CompactSerialize()
			Expect(err).NotTo(HaveOccurred())

			res, err = notary.Notarize(token)
		})

		Context("when the public key is not set", func() {
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
					Expect(res["aud"]).To(ConsistOf("audience"))
				})
			})
		})

		Context("when the public key is not correct", func() {
			BeforeEach(func() {
				randomKey, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).NotTo(HaveOccurred())

				notary = authorizer.NewNotary(
					authorizer.WithPublicKey(&randomKey.PublicKey),
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
					Expect(res["aud"]).To(ConsistOf("audience"))
				})
			})
		})

		Context("when the public key is set", func() {
			BeforeEach(func() {
				notary = authorizer.NewNotary(
					authorizer.WithPublicKey(&privateKey.PublicKey),
					authorizer.WithAudience("audience-1", "audience-2"),
					authorizer.WithTarget(server.URL()+"/token_keys"),
				)
			})

			Context("when the token is expired", func() {
				BeforeEach(func() {
					claims.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
				})

				It("errors", func() {
					Expect(err).To(Equal(authorizer.ErrTokenExpired))
				})
			})

			Context("when the token is not expired", func() {
				BeforeEach(func() {
					claims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Minute))
				})

				Context("when the audience is not valid", func() {
					BeforeEach(func() {
						claims.Audience = jwt.Audience{"not-audience"}
					})

					It("errors", func() {
						Expect(err).To(Equal(authorizer.ErrInvalidAudience))
					})
				})

				Context("when the audience is valid", func() {
					BeforeEach(func() {
						claims.Audience = jwt.Audience{"audience-1"}
					})

					It("validates the token", func() {
						Expect(err).NotTo(HaveOccurred())
						Expect(res["sub"]).To(Equal("subject"))
						Expect(res["iss"]).To(Equal("issuer"))
						Expect(res["aud"]).To(ConsistOf("audience-1"))
					})
				})
			})
		})
	})
})
