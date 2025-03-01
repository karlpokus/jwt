package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

var ErrBadSigningAlg = errors.New("bad signing algorithm")
var ErrBadJWKSKey = errors.New("bad JWKS key")

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

type OIDConfig struct {
	JWKSURI string `json:"jwks_uri"`
}

func GetKey(ctx context.Context, issuer string, header map[string]any) (*rsa.PublicKey, error) {
	jwks, err := getKeyMaterial(ctx, issuer)
	if err != nil {
		return nil, err
	}
	// TODO: token algo and JWKS algo must match
	return assembleKey(jwks, header)
}

func getKeyMaterial(ctx context.Context, issuer string) (*JWKS, error) {
	url := fmt.Sprintf("%s/%s", issuer, ".well-known/openid-configuration")
	b, err := getURL(ctx, url)
	if err != nil {
		return nil, err
	}
	var conf OIDConfig
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return nil, err
	}
	b, err = getURL(ctx, conf.JWKSURI)
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

func getURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
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
