package keyfetch

import (
	"testing"
	"time"

	"git.rootprojects.org/root/keypairs"
	"git.rootprojects.org/root/keypairs/keyfetch/uncached"
)

var pubkey keypairs.PublicKey

func TestCachesKey(t *testing.T) {
	// TODO set KeyID() in cache
	testCachesKey(t, "https://bigsquid.auth0.com/")
	clear()
	testCachesKey(t, "https://bigsquid.auth0.com")
	// Get PEM
	pubk3, err := PEM("https://bigsquid.auth0.com/pem")
	if nil != err {
		t.Fatal("[0] Error fetching and caching key:", err)
	}
	thumb3 := keypairs.Thumbprint(pubk3)
	thumb := keypairs.Thumbprint(pubkey)
	if thumb3 != thumb {
		t.Fatalf("Error got different thumbprint for different versions of the same key %q != %q: %v", thumb3, thumb, err)
	}
	clear()
	testCachesKey(t, "https://big-squid.github.io/")
}

func TestKnownKID(t *testing.T) {
	url := "https://kraken-dev.auth0.com"
	kid := "RkVGNTM5NDc4NkM4NjA5OEMxMTNCMTNBQ0RGRDA0MEQ0RDNDMkM3Qw"
	_, err := OIDCJWK(kid, url)
	if nil != err {
		t.Fatal(url, err)
	}
}

func testCachesKey(t *testing.T, url string) {
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
		key = keys[i].Key()
		break
	}
	thumb := keypairs.Thumbprint(key)

	// Look in cache for each (and fail)
	if pub := Get(thumb, ""); nil != pub {
		t.Fatal("SANITY: Should not have any key cached by thumbprint")
	}

	// Get with caching
	pubkey, err = OIDCJWK(thumb, url)
	if nil != err {
		t.Fatal("[1] Error fetching and caching key:", err)
	}

	// Look in cache for each (and succeed)
	if pub := Get(thumb, ""); nil == pub {
		t.Fatal("key was not properly cached by thumbprint", thumb)
	}

	// TODO thumb / id mapping
	thumb = keypairs.Thumbprint(pubkey)
	if pub := Get(thumb, url); nil == pub {
		t.Fatal("key was not properly cached by kid", pubkey)
	}
	// TODO
	/*
	if 0 == len(keyfetch.GetID(thumb)) {
		t.Log("Key did not have an explicit KeyID", thumb)
	}
	*/

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
	if !key.Equal(pubkey) || keypairs.Thumbprint(key) != keypairs.Thumbprint(pubkey) {
		t.Fatalf("SANITY: [todo: KeyIDs or] Thumbprints do not match:\n%q != %q\n%q != %q",
			keypairs.Thumbprint(key), keypairs.Thumbprint(pubkey),
			keypairs.Thumbprint(key), keypairs.Thumbprint(pubkey))
	}

	// Get 404
	_, err = PEM(url + "/will-not-be-found.xyz")
	if nil == err {
		t.Fatal("Should have an error when retrieving a 404 or index.html:", err)
	}
}
