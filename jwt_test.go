package jwt

import (
	"log"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerify(t *testing.T) {
	b, err := os.ReadFile("testdata/priv.key")
	if err != nil {
		log.Fatal(err)
	}
	priv, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{
		"foo": "bar",
	}
	s, err := New(priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/pub.key")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(pub, s)
	if err != nil {
		t.Fatal(err)
	}
}
