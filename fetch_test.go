package keypairs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
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
	url := "https://bigsquid.auth0.com/"

	// Raw fetch a key and get KID and Thumbprint
	_, keys, err := fetchOIDCPublicKeys(url)
	if nil != err {
		t.Fatal(url, err)
	}
	if 0 == len(keys) {
		t.Fatal("Should discover 1 or more keys via", url)
	}

	var key PublicKey
	for i := range keys {
		key = keys[i]
		break
	}
	thumb := key.Thumbprint()

	// Look in cache for each (and fail)
	if _, ok := hasPublicKeyByThumbprint(thumb); ok {
		t.Fatal("SANITY: Should not have any key cached by thumbprint")
	}
	if _, ok := hasPublicKey(key.KeyID(), url); ok {
		t.Fatal("SANITY: Should not have any key cached by kid")
	}

	// Get with caching
	k2, err := GetPublicKey(thumb, url)
	if nil != err {
		t.Fatal("Error fetching and caching key:", err)
	}

	// Look in cache for each (and succeed)
	if _, ok := hasPublicKeyByThumbprint(thumb); !ok {
		t.Fatal("key was not properly cached by thumbprint")
	}
	if "" != k2.KeyID() {
		if _, ok := hasPublicKeyByThumbprint(thumb); !ok {
			t.Fatal("key was not properly cached by thumbprint")
		}
	} else {
		t.Log("Key did not have an explicit KeyID")
	}

	// Get again (should be sub-ms instant)
	now := time.Now()
	_, err = GetPublicKey(thumb, url)
	if nil != err {
		t.Fatal("SANITY: Failed to get the key we just got...", err)
	}
	if time.Now().Sub(now) > time.Millisecond {
		t.Fatal("Failed to cache key by thumbprint...", time.Now().Sub(now))
	}

	// Sanity check that the kid and thumb match
	if key.KeyID() != k2.KeyID() || key.Thumbprint() != k2.Thumbprint() {
		t.Fatal("SANITY: KeyIDs or Thumbprints do not match:", key.KeyID(), k2.KeyID(), key.Thumbprint(), k2.Thumbprint())
	}
}
