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
		keys, err := FetchOIDCPublicKeys(url)
		if nil != err {
			t.Fatal(url, err)
		}

		for i := range keys {
			switch key := keys[i].(type) {
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
