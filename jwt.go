package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlpokus/ago"

	"github.com/fatih/color"
)

type Token struct {
	JWT               *jwt.Token
	SignatureVerified bool
}

type JWKSKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"` // RSA exponent
	N   string `json:"n"` // RSA modulus
	Kid string `json:"kid"`
	Kty string `json:"kty"`
}

type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

func (t *Token) String() string {
	c := color.New(color.FgMagenta, color.Bold)
	header := t.JWT.Header
	claims, ok := t.JWT.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("oops!")
	}
	// print standard claims under TL;DR
	c.Println("TL;DR")
	iat, err := claims.GetIssuedAt()
	if err != nil {
		log.Printf("bad issue date: %s", err)
	} else {
		log.Printf("issued %s", ago.ParseWithContext(iat.Time))
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Printf("bad expiration: %s", err)
	} else {
		log.Printf("expires %s", ago.ParseWithContext(exp.Time))
	}
	iss, err := claims.GetIssuer()
	if err != nil {
		log.Printf("bad issuer: %s", err)
	} else {
		log.Printf("issued by %s", iss)
	}
	aud, err := claims.GetAudience()
	if err != nil {
		log.Printf("bad audience: %s", err)
	} else {
		log.Printf("audience %s", aud)
	}
	log.Printf("signature verified: %t", t.SignatureVerified)
	c.Println("HEADERS")
	for k, v := range header {
		log.Printf("%s:%s", k, v)
	}
	c.Println("CLAIMS")
	for k, v := range claims {
		num, ok := v.(float64)
		if ok {
			log.Printf("%s:%d", k, int(num))
			continue
		}
		log.Printf("%s:%s", k, v)
	}
	return ""
}

var ErrInvalidToken = errors.New("invalid token")
var ErrBadClaims = errors.New("bad claims")
var ErrBadSigningAlg = errors.New("bad signing algorithm")
var ErrBadJWKSKey = errors.New("bad JWKS key")

func New(key *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

func Verify(key *rsa.PublicKey, token string) error {
	// Parse verifies a bunch of things by default:
	//
	//   sig
	//   claims: exp, nbf, iat, aud (requires an audience to check)
	//   iss, sub
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return err
	}
	if !t.Valid {
		return ErrInvalidToken
	}
	return nil
}

func Read(b []byte) (*Token, error) {
	tokenString := string(b)
	p := jwt.NewParser()
	t, _, err := p.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	// verify with JWKS
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrBadClaims
	}
	// is issuer required?
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	jwks, err := getKeyMaterial(ctx, issuer)
	if err != nil {
		return nil, err
	}
	key, err := assembleKey(jwks, t.Header)
	if err != nil {
		return nil, err
	}
	token := &Token{JWT: t}
	err = Verify(key, tokenString)
	if err == nil {
		token.SignatureVerified = true
	} else {
		log.Printf("token validation error: %s", err)
	}
	return token, nil
}

func getKeyMaterial(ctx context.Context, issuer string) (*JWKS, error) {
	url := fmt.Sprintf("%s/%s", issuer, ".well-known/jwks.json")
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var jwks JWKS
	err = json.Unmarshal(b, &jwks)
	if err != nil {
		return nil, err
	}
	return &jwks, nil
}

func assembleKey(jwks *JWKS, header map[string]any) (*rsa.PublicKey, error) {
	alg := header["alg"].(string)
	kid := header["kid"].(string)
	if alg != "RS256" {
		return nil, ErrBadSigningAlg
	}
	var k JWKSKey
	var found bool
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			k = key
			found = true
			break
		}
	}
	if !found {
		return nil, ErrBadJWKSKey
	}
	if k.Kty != "RSA" {
		return nil, ErrBadJWKSKey
	}
	return assembleBytes(k)
}

func assembleBytes(k JWKSKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0)
	n.SetBytes(nBytes)
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := big.NewInt(0)
	e.SetBytes(eBytes)
	return &rsa.PublicKey{
		N: n,
		E: int(e.Uint64()),
	}, nil
}
