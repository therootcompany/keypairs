package keyfetch

import (
	"testing"
	"time"

	keypairs "github.com/big-squid/go-keypairs"
	"github.com/big-squid/go-keypairs/keyfetch/uncached"
)

func TestCachesKey(t *testing.T) {
	url := "https://bigsquid.auth0.com/"

	// Raw fetch a key and get KID and Thumbprint
	_, keys, err := uncached.OIDCJWKs(url)
	if nil != err {
		t.Fatal(url, err)
	}
	if 0 == len(keys) {
		t.Fatal("Should discover 1 or more keys via", url)
	}

	var key keypairs.PublicKey
	for i := range keys {
		key = keys[i]
		break
	}
	thumb := key.Thumbprint()

	// Look in cache for each (and fail)
	if pub := Get(thumb, ""); nil != pub {
		t.Fatal("SANITY: Should not have any key cached by thumbprint")
	}

	// Get with caching
	k2, err := OIDCJWK(thumb, url)
	if nil != err {
		t.Fatal("Error fetching and caching key:", err)
	}

	// Look in cache for each (and succeed)
	if pub := Get(thumb, ""); nil == pub {
		t.Fatal("key was not properly cached by thumbprint", thumb)
	}
	if "" != k2.KeyID() {
		if pub := Get(k2.KeyID(), url); nil == pub {
			t.Fatal("key was not properly cached by kid", k2.KeyID())
		}
	} else {
		t.Log("Key did not have an explicit KeyID")
	}

	// Get again (should be sub-ms instant)
	now := time.Now()
	_, err = OIDCJWK(thumb, url)
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
