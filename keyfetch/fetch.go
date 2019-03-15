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
	"net/http"
	"net/url"
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

// PEM tries to return a key from cache, falling back to the specified PEM url
func PEM(url string) (keypairs.PublicKey, error) {
	// url is kid in this case
	return immediateOneOrFetch(url, url, func(string) (map[string]map[string]string, map[string]keypairs.PublicKey, error) {
		m, key, err := uncached.PEM(url)
		if nil != err {
			return nil, nil, err
		}

		// put in a map, just for caching
		maps := map[string]map[string]string{}
		maps[key.Thumbprint()] = m
		maps[url] = m

		keys := map[string]keypairs.PublicKey{}
		keys[key.Thumbprint()] = key
		keys[url] = key

		return maps, keys, nil
	})
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

/*
  IsTrustedIssuer returns true when the `iss` (i.e. from a token) matches one
  in the provided whitelist (also matches wildcard domains).

  You may explicitly allow insecure http (i.e. for automated testing) by
  including http:// Otherwise the scheme in each item of the whitelist should
	include the "https://" prefix.

  SECURITY CONSIDERATIONS (Please Read)

  You'll notice that *http.Request is optional. It should only be used under these
  three circumstances:

    1) Something else guarantees http -> https redirection happens before the
       connection gets here AND this server directly handles TLS/SSL.

    2) If you're using a load balancer or web server, and this doesn't handle
       TLS/SSL directly, that server is _explicitly_ configured to protect
       against Domain Fronting attacks. As of 2019, most web servers and load
       balancers do not protect against that by default.

    3) If you only use it to make your automated integration testing more
       and it isn't enabled in production.

  Otherwise, DO NOT pass in *http.Request as you will introduce a 0-day
  vulnerability allowing an attacker to spoof any token issuer of their choice.
  The only reason I allowed this in a public library where non-experts would
  encounter it is to make testing easier.
*/
func IsTrustedIssuer(iss string, whitelist Whitelist, rs ...*http.Request) bool {
	// Normalize the http:// and https:// and parse
	iss = strings.TrimRight(iss, "/") + "/"
	if strings.HasPrefix(iss, "http://") {
		// ignore
	} else if strings.HasPrefix(iss, "//") {
		return false // TODO
	} else if !strings.HasPrefix(iss, "https://") {
		iss = "https://" + iss
	}
	issURL, err := url.Parse(iss)
	if nil != err {
		return false
	}

	// Check that
	// * schemes match (https: == https:)
	// * paths match (/foo/ == /foo/, always with trailing slash added)
	// * hostnames are compatible (a == b or "sub.foo.com".HasSufix(".foo.com"))
	for i := range []*url.URL(whitelist) {
		u := whitelist[i]

		if issURL.Scheme != u.Scheme {
			continue
		} else if u.Path != strings.TrimRight(issURL.Path, "/")+"/" {
			continue
		} else if issURL.Host != u.Host {
			if '.' == u.Host[0] && strings.HasSuffix(issURL.Host, u.Host) {
				return true
			}
			continue
		}
		// All failures have been handled
		return true
	}

	// Check if implicit issuer is available
	if 0 == len(rs) {
		return false
	}
	return hasImplicitTrust(issURL, rs[0])
}

// hasImplicitTrust relies on the security of DNS and TLS to determine if the
// headers of the request can be trusted as identifying the server itself as
// a valid issuer, without additional configuration.
//
// Helpful for testing, but in the wrong hands could easily lead to a zero-day.
func hasImplicitTrust(issURL *url.URL, r *http.Request) bool {
	if nil == r {
		return false
	}

	// Sanity check that, if a load balancer exists, it isn't misconfigured
	proto := r.Header.Get("X-Forwarded-Proto")
	if "" != proto && proto != "https" {
		return false
	}

	// Get the host
	// * If TLS, block Domain Fronting
	// * Otherwise assume trusted proxy
	// * Otherwise assume test environment
	var host string
	if nil != r.TLS {
		// Note that if this were to be implemented for HTTP/2 it would need to
		// check all names on the certificate, not just the one with which the
		// original connection was established. However, not our problem here.
		// See https://serverfault.com/a/908087/93930
		if r.TLS.ServerName != r.Host {
			return false
		}
		host = r.Host
	} else {
		host = r.Header.Get("X-Forwarded-Host")
		if "" == host {
			host = r.Host
		}
	}

	// Same tests as above, adjusted since it can't handle wildcards and, since
	// the path is variable, we make the assumption that a child can trust a
	// parent, but that a parent cannot trust a child.
	if r.Host != issURL.Host {
		return false
	}
	if !strings.HasPrefix(strings.TrimRight(r.URL.Path, "/")+"/", issURL.Path) {
		// Ex: Request URL                                   Token Issuer
		// !"https:example.com/johndoe/api/dothing".HasPrefix("https:example.com/")
		return false
	}

	return true
}

// Whitelist
type Whitelist []*url.URL

// NewWhitelist turns an array of URLs (such as https://example.com/) into
// a parsed array of *url.URLs that can be used by the IsTrustedIssuer function
func NewWhitelist(issuers []string, insecures ...bool) (Whitelist, error) {
	list := []*url.URL{}
	insecure := false
	if 0 != len(insecures) && insecures[0] {
		insecure = true
	}

	for i := range issuers {
		iss := issuers[i]
		if strings.HasPrefix(iss, "http://") {
			if !insecure {
				return nil, errors.New("Oops! You have an insecure domain in your whitelist: " + iss)
			}
		} else if strings.HasPrefix(iss, "//") {
			// TODO
			return nil, errors.New("Rather than prefixing with // to support multiple protocols, add them seperately:" + iss)
		} else if !strings.HasPrefix(iss, "https://") {
			iss = "https://" + iss
		}
		// trailing slash as a boundary character, which may or may not denote a directory
		iss = strings.TrimRight(iss, "/") + "/"
		u, err := url.Parse(iss)
		if nil != err {
			return nil, err
		}
		if strings.HasPrefix(u.Host, "*.") {
			u.Host = u.Host[1:]
		}
		list = append(list, u)
	}

	return Whitelist(list), nil
}
