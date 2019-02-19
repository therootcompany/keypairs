package keypairs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestFetchOIDCPublicKeys(t *testing.T) {
	urls := []string{
		//"https://bigsquid.auth0.com/.well-known/jwks.json",
		"https://bigsquid.auth0.com/",
		"https://api-dev.bigsquid.com/",
	}
	for i := range urls {
		url := urls[i]
		_, keys, err := fetchOIDCPublicKeys(url)
		if nil != err {
			t.Fatal(url, err)
		}

		for kid := range keys {
			switch key := keys[kid].Key().(type) {
			case *rsa.PublicKey:
				_ = ThumbprintRSAPublicKey(key)
			case *ecdsa.PublicKey:
				_ = ThumbprintECPublicKey(key)
			default:
				t.Fatal(errors.New("unsupported interface type"))
			}
		}
	}
}

func TestCachesKey(t *testing.T) {
	// Raw fetch a key and get KID and Thumbprint
	// Look in cache for each (and fail)
	// Get with caching
	// Look in cache for each (and succeed)
	// Get again (should be sub-ms instant)
}
