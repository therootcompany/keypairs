// Package keyfetch retrieve and cache PublicKeys
// from OIDC (https://example.com/.well-known/openid-configuration)
// and Auth0 (https://example.com/.well-known/jwks.json)
// JWKs URLs and expires them when `exp` is reached
// (or a default expiry if the key does not provide one).
// It uses the keypairs package to Unmarshal the JWKs into their
// native types (with a very thin shim to provide the type safety
// that Go's crypto.PublicKey and crypto.PrivateKey interfaces lack).
package keyfetch

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	keypairs "github.com/big-squid/go-keypairs"
	"github.com/big-squid/go-keypairs/keyfetch/uncached"
)

var EInvalidJWKURL = errors.New("url does not lead to valid JWKs")
var KeyCache = map[string]CachableKey{}
var KeyCacheMux = sync.Mutex{}

type CachableKey struct {
	Key    keypairs.PublicKey
	Expiry time.Time
}

// maybe TODO use this poor-man's enum to allow kids thumbs to be accepted by the same method?
/*
type KeyID string

func (kid KeyID) ID() string {
	return string(kid)
}
func (kid KeyID) isID() {}

type Thumbprint string

func (thumb Thumbprint) ID() string {
	return string(thumb)
}
func (thumb Thumbprint) isID() {}

type ID interface {
	ID() string
	isID()
}
*/

var StaleTime = 15 * time.Minute
var DefaultKeyDuration = 48 * time.Hour
var MinimumKeyDuration = time.Hour
var MaximumKeyDuration = 72 * time.Hour

type publicKeysMap map[string]keypairs.PublicKey

// FetchOIDCPublicKeys fetches baseURL + ".well-known/openid-configuration" and then returns FetchPublicKeys(jwks_uri).
func OIDCJWKs(baseURL string) (publicKeysMap, error) {
	if maps, keys, err := uncached.OIDCJWKs(baseURL); nil != err {
		return nil, err
	} else {
		cacheKeys(maps, keys, baseURL)
		return keys, err
	}
}

func OIDCJWK(kidOrThumb, iss string) (keypairs.PublicKey, error) {
	return immediateOneOrFetch(kidOrThumb, iss, uncached.OIDCJWKs)
}

func WellKnownJWKs(kidOrThumb, iss string) (publicKeysMap, error) {
	if maps, keys, err := uncached.WellKnownJWKs(iss); nil != err {
		return nil, err
	} else {
		cacheKeys(maps, keys, iss)
		return keys, err
	}
}

func WellKnownJWK(kidOrThumb, iss string) (keypairs.PublicKey, error) {
	return immediateOneOrFetch(kidOrThumb, iss, uncached.WellKnownJWKs)
}

// JWKs returns a map of keys identified by their thumbprint
// (since kid may or may not be present)
func JWKs(jwksurl string) (publicKeysMap, error) {
	if maps, keys, err := uncached.JWKs(jwksurl); nil != err {
		return nil, err
	} else {
		iss := strings.Replace(jwksurl, ".well-known/jwks.json", "", 1)
		cacheKeys(maps, keys, iss)
		return keys, err
	}
}

// JWK tries to return a key from cache, falling back to the /.well-known/jwks.json of the issuer
func JWK(kidOrThumb, iss string) (keypairs.PublicKey, error) {
	return immediateOneOrFetch(kidOrThumb, iss, uncached.JWKs)
}

// Fetch returns a key from cache, falling back to an exact url as the "issuer"
func Fetch(url string) (keypairs.PublicKey, error) {
	// url is kid in this case
	return immediateOneOrFetch(url, url, func(string) (map[string]map[string]string, map[string]keypairs.PublicKey, error) {
		m, key, err := uncached.Fetch(url)
		if nil != err {
			return nil, nil, err
		}

		// put in a map, just for caching
		maps := map[string]map[string]string{}
		maps[key.Thumbprint()] = m

		keys := map[string]keypairs.PublicKey{}
		keys[key.Thumbprint()] = key

		return maps, keys, nil
	})
}

// Get retrieves a key from cache, or returns an error.
// The issuer string may be empty if using a thumbprint rather than a kid.
func Get(kidOrThumb, iss string) keypairs.PublicKey {
	if pub := get(kidOrThumb, iss); nil != pub {
		return pub.Key
	}
	return nil
}

func get(kidOrThumb, iss string) *CachableKey {
	iss = normalizeIssuer(iss)
	KeyCacheMux.Lock()
	defer KeyCacheMux.Unlock()

	// we're safe to check the cache by kid alone
	// by virtue that we never set it by kid alone
	hit, ok := KeyCache[kidOrThumb]
	if ok {
		if now := time.Now(); hit.Expiry.Sub(now) > 0 {
			// only return non-expired keys
			return &hit
		}
	}

	id := kidOrThumb + "@" + iss
	hit, ok = KeyCache[id]
	if ok {
		if now := time.Now(); hit.Expiry.Sub(now) > 0 {
			// only return non-expired keys
			return &hit
		}
	}

	return nil
}

func immediateOneOrFetch(kidOrThumb, iss string, fetcher myfetcher) (keypairs.PublicKey, error) {
	now := time.Now()
	key := get(kidOrThumb, iss)

	if nil == key {
		return fetchAndSelect(kidOrThumb, iss, fetcher)
	}

	// Fetch just a little before the key actually expires
	if key.Expiry.Sub(now) <= StaleTime {
		go fetchAndSelect(kidOrThumb, iss, fetcher)
	}

	return key.Key, nil
}

type myfetcher func(string) (map[string]map[string]string, map[string]keypairs.PublicKey, error)

func fetchAndSelect(id, baseURL string, fetcher myfetcher) (keypairs.PublicKey, error) {
	maps, keys, err := fetcher(baseURL)
	if nil != err {
		return nil, err
	}
	cacheKeys(maps, keys, baseURL)

	for i := range keys {
		key := keys[i]

		if id == key.Thumbprint() {
			return key, nil
		}

		if id == key.KeyID() {
			return key, nil
		}
	}

	return nil, fmt.Errorf("Key identified by '%s' was not found at %s", id, baseURL)
}

func cacheKeys(maps map[string]map[string]string, keys map[string]keypairs.PublicKey, issuer string) {
	for i := range keys {
		key := keys[i]
		m := maps[i]
		iss := issuer
		if "" != m["iss"] {
			iss = m["iss"]
		}
		iss = normalizeIssuer(iss)
		cacheKey(m["kid"], iss, m["exp"], key)
	}
}

func cacheKey(kid, iss, expstr string, pub keypairs.PublicKey) error {
	var expiry time.Time
	iss = normalizeIssuer(iss)

	exp, _ := strconv.ParseInt(expstr, 10, 64)
	if 0 == exp {
		// use default
		expiry = time.Now().Add(DefaultKeyDuration)
	} else if exp < time.Now().Add(MinimumKeyDuration).Unix() || exp > time.Now().Add(MaximumKeyDuration).Unix() {
		// use at least one hour
		expiry = time.Now().Add(MinimumKeyDuration)
	} else {
		expiry = time.Unix(exp, 0)
	}

	KeyCacheMux.Lock()
	defer KeyCacheMux.Unlock()
	// Put the key in the cache by both kid and thumbprint, and set the expiry
	id := kid + "@" + iss
	KeyCache[id] = CachableKey{
		Key:    pub,
		Expiry: expiry,
	}
	// Since thumbprints are crypto secure, iss isn't needed
	thumb := pub.Thumbprint()
	KeyCache[thumb] = CachableKey{
		Key:    pub,
		Expiry: expiry,
	}

	return nil
}

func clear() {
	KeyCacheMux.Lock()
	defer KeyCacheMux.Unlock()
	KeyCache = map[string]CachableKey{}
}

func normalizeIssuer(iss string) string {
	return strings.TrimRight(iss, "/")
}
