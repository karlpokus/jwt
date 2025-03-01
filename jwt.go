package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlpokus/ago"
	"github.com/karlpokus/jwt/jwks"

	"github.com/fatih/color"
)

var ErrInvalidToken = errors.New("invalid token")
var ErrBadClaims = errors.New("bad claims")

type Token struct {
	JWT               *jwt.Token
	SignatureVerified bool
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
		if num, ok := v.(float64); ok {
			log.Printf("%s:%d", k, int(num))
			continue
		}
		if t, ok := v.(bool); ok {
			log.Printf("%s:%t", k, t)
			continue
		}
		log.Printf("%s:%s", k, v)
	}
	return ""
}

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
	keyFunc := func(t *jwt.Token) (any, error) {
		return key, nil
	}
	// jwt.WithIssuer()
	// jwt.WithAudience()
	t, err := jwt.Parse(token, keyFunc, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
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
	key, err := jwks.GetKey(ctx, issuer, t.Header)
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
