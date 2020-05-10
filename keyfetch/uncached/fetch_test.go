package uncached

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"

	"git.rootprojects.org/root/keypairs"
)

func TestJWKs(t *testing.T) {
	urls := []string{
		"https://bigsquid.auth0.com/.well-known/jwks.json",
	}
	for i := range urls {
		url := urls[i]
		_, keys, err := JWKs(url)
		if nil != err {
			t.Fatal(url, err)
		}

		for kid := range keys {
			switch key := keys[kid].Key().(type) {
			case *rsa.PublicKey:
				_ = keypairs.ThumbprintRSAPublicKey(key)
			case *ecdsa.PublicKey:
				_ = keypairs.ThumbprintECPublicKey(key)
			default:
				t.Fatal(errors.New("unsupported interface type"))
			}
		}
	}
}

func TestWellKnownJWKs(t *testing.T) {
	urls := []string{
		//"https://bigsquid.auth0.com/.well-known/jwks.json"
		"https://bigsquid.auth0.com/",
	}
	for i := range urls {
		url := urls[i]
		_, keys, err := WellKnownJWKs(url)
		if nil != err {
			t.Fatal(url, err)
		}

		for kid := range keys {
			switch key := keys[kid].Key().(type) {
			case *rsa.PublicKey:
				_ = keypairs.ThumbprintRSAPublicKey(key)
			case *ecdsa.PublicKey:
				_ = keypairs.ThumbprintECPublicKey(key)
			default:
				t.Fatal(errors.New("unsupported interface type"))
			}
		}
	}
}

func TestOIDCJWKs(t *testing.T) {
	urls := []string{
		//"https://bigsquid.auth0.com/.well-known/openid-configuration"
		//"https://bigsquid.auth0.com/.well-known/jwks.json"
		"https://bigsquid.auth0.com/",
	}
	for i := range urls {
		url := urls[i]
		_, keys, err := OIDCJWKs(url)
		if nil != err {
			t.Fatal(url, err)
		}

		for kid := range keys {
			switch key := keys[kid].Key().(type) {
			case *rsa.PublicKey:
				_ = keypairs.ThumbprintRSAPublicKey(key)
			case *ecdsa.PublicKey:
				_ = keypairs.ThumbprintECPublicKey(key)
			default:
				t.Fatal(errors.New("unsupported interface type"))
			}
		}
	}
}
