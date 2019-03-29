package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func init() {
	// force check if private and public are pairs
	if err := Parse(Sign(Claims{}), &Claims{}); err != nil {
		panic(err)
	}
}

const refExp = 1 * 24 * 3600  // refresh every 1 day.
const maxExp = 30 * 24 * 3600 // max expire 30 days.

type Claims struct {
	Issuer   string `json:"iss,omitempty"` // who created
	UserId   string `json:"sub,omitempty"`
	Audience string `json:"aud,omitempty"` // default *
	IssuedAt int64  `json:"iat,omitempty"`
	Session  string `json:"ses,omitempty"` // session for
	CorpId   string `json:"cid,omitempty"`
	Role     int64  `json:"rol,omitempty"` // bit mask
}

// Valid check is claims is not expired
func (c Claims) Valid() error {
	if c.IssuedAt > 0 && time.Now().Unix() > c.IssuedAt+maxExp {
		return errors.New("token expired")
	}
	return nil
}

// Refresh set createAt timestamp
func (c *Claims) Refresh() {
	c.IssuedAt = time.Now().Unix()
}

// NeedRefresh returns if token need refresh
func (c *Claims) NeedRefresh() bool {
	return time.Now().Unix() > c.IssuedAt+refExp
}

func (c *Claims) Sign() string {
	if c.IssuedAt == 0 {
		c.Refresh()
	}

	return Sign(c)
}

// openssl ecparam -genkey -name prime256v1 -noout -out private.pem
var privateKeyData = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMglXG9YR4UsR4/Te+3yI3/lyokp8fxuEJvhFDXE9GFAoAoGCCqGSM49
AwEHoUQDQgAEAf0bqKQ5jYOZPBreBXKkGF2vjsyFaMKmPRxpqJKPOEAmQQFfRRHs
ufiLBlH/oxVSwu14Zz7mWSTsStnk3dpD3A==
-----END EC PRIVATE KEY-----
`)

var privateKey = func() *ecdsa.PrivateKey {
	if keyStr := os.Getenv("jwt_ecdsa_private"); keyStr != "" {
		var err error
		privateKeyData, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			panic(err)
		}
	}
	pk, err := jwt.ParseECPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		panic(err)
	}
	return pk
}()

// Sign gen token with given claims
func Sign(c jwt.Claims) string {
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodES256, c).SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return tokenStr
}

// openssl ec -in private.pem -pubout -out public.pem
var publicKeyData = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAf0bqKQ5jYOZPBreBXKkGF2vjsyF
aMKmPRxpqJKPOEAmQQFfRRHsufiLBlH/oxVSwu14Zz7mWSTsStnk3dpD3A==
-----END PUBLIC KEY-----
`)

var publicKey = func() *ecdsa.PublicKey {
	if keyStr := os.Getenv("jwt_ecdsa_public"); keyStr != "" {
		var err error
		publicKeyData, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			panic(err)
		}
	}
	pk, err := jwt.ParseECPublicKeyFromPEM(publicKeyData)
	if err != nil {
		panic(err)
	}
	return pk
}()

// Parse convert token to *cliams
func Parse(tokenStr string, c jwt.Claims) error {
	_, err := jwt.ParseWithClaims(tokenStr, c, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	return err
}
