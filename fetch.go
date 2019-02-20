package keypairs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var EInvalidJWKURL = errors.New("url does not lead to valid JWKs")
var KeyCache = map[string]CachableKey{}
var KeyCacheMux = sync.Mutex{}

type CachableKey struct {
	Key    PublicKey
	Expiry time.Time
}

// TODO use this poor-man's enum to allow kids thumbs to be accepted by the same method
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

// FetchOIDCPublicKeys fetches baseURL + ".well-known/openid-configuration" and then returns FetchPublicKeys(jwks_uri).
func FetchOIDCPublicKeys(baseURL string) (map[string]PublicKey, error) {
	if _, keys, err := fetchAndCacheOIDCPublicKeys(baseURL); nil != err {
		return nil, err
	} else {
		return keys, err
	}
}

func fetchAndCacheOIDCPublicKeys(baseURL string) (map[string]map[string]string, map[string]PublicKey, error) {
	if maps, keys, err := fetchOIDCPublicKeys(baseURL); nil != err {
		return nil, nil, err
	} else {
		cacheKeys(maps, keys, baseURL)
		return maps, keys, err
	}
}

func fetchOIDCPublicKeys(baseURL string) (map[string]map[string]string, map[string]PublicKey, error) {
	oidcConf := struct {
		JWKSURI string `json:"jwks_uri"`
	}{}

	// must come in as https://<domain>/
	url := baseURL + ".well-known/openid-configuration"
	err := safeFetch(url, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		decoder.UseNumber()
		return decoder.Decode(&oidcConf)
	})
	if nil != err {
		return nil, nil, err
	}

	return fetchPublicKeys(oidcConf.JWKSURI)
}

func FetchOIDCPublicKey(id, baseURL string) (PublicKey, error) {
	return fetchOIDCPublicKey(id, baseURL, fetchAndCacheOIDCPublicKeys)
}
func fetchOIDCPublicKey(id, baseURL string, fetcher func(string) (map[string]map[string]string, map[string]PublicKey, error)) (PublicKey, error) {
	_, keys, err := fetcher(baseURL)
	if nil != err {
		return nil, err
	}

	for i := range keys {
		key := keys[i]

		if id == key.Thumbprint() {
			return key, nil
		}

		var kid string
		switch k := key.(type) {
		case *RSAPublicKey:
			kid = k.KID
		case *ECPublicKey:
			kid = k.KID
		default:
			panic(errors.New("Developer Error: Only ECPublicKey and RSAPublicKey are handled"))
		}
		if id == kid {
			return key, nil
		}
	}

	return nil, fmt.Errorf("Key identified by '%s' was not found at %s", id, baseURL)
}

// FetchPublicKeys returns a map of keys identified by their kid or thumbprint (if kid is not specified)
func FetchPublicKeys(jwksurl string) (map[string]PublicKey, error) {
	if maps, keys, err := fetchPublicKeys(jwksurl); nil != err {
		return nil, err
	} else {
		cacheKeys(maps, keys, strings.Replace(jwksurl, ".well-known/jwks.json", "", 1))
		return keys, err
	}
}

func fetchPublicKeys(jwksurl string) (map[string]map[string]string, map[string]PublicKey, error) {
	keys := map[string]PublicKey{}
	maps := map[string]map[string]string{}
	resp := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: make([]map[string]interface{}, 0, 1),
	}

	if err := safeFetch(jwksurl, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		decoder.UseNumber()
		return decoder.Decode(&resp)
	}); nil != err {
		return nil, nil, err
	}

	for i := range resp.Keys {
		k := resp.Keys[i]
		m := getStringMap(k)

		if key, err := NewJWKPublicKey(m); nil != err {
			return nil, nil, err
		} else {
			keys[key.Thumbprint()] = key
			maps[key.Thumbprint()] = m
		}
	}

	return maps, keys, nil
}

// FetchPublicKey retrieves a JWK from a URL that specifies only one
func FetchPublicKey(url string) (PublicKey, error) {
	m, key, err := fetchPublicKey(url)
	if nil != err {
		return nil, err
	}

	maps := map[string]map[string]string{}
	maps[key.Thumbprint()] = m

	keys := map[string]PublicKey{}
	keys[key.Thumbprint()] = key

	cacheKeys(maps, keys, url)

	return key, nil
}

func fetchPublicKey(url string) (map[string]string, PublicKey, error) {
	var m map[string]interface{}
	if err := safeFetch(url, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		decoder.UseNumber()
		return decoder.Decode(&m)
	}); nil != err {
		return nil, nil, err
	}

	n := getStringMap(m)
	key, err := NewJWKPublicKey(n)
	if nil != err {
		return nil, nil, err
	}

	return n, key, nil
}

func hasPublicKey(kid, iss string) (*CachableKey, bool) {
	id := kid + "@" + iss

	KeyCacheMux.Lock()
	hit, ok := KeyCache[id]
	KeyCacheMux.Unlock()

	if now := time.Now(); ok && hit.Expiry.Sub(now) > 0 {
		return &hit, true
	}

	return nil, false
}

// it would be a security risk to pass kid as a thumbprint
func hasPublicKeyByThumbprint(thumb string) (*CachableKey, bool) {
	KeyCacheMux.Lock()
	hit, ok := KeyCache[thumb]
	KeyCacheMux.Unlock()

	if now := time.Now(); ok && hit.Expiry.Sub(now) > 0 {
		return &hit, true
	}

	return nil, false
}

func GetPublicKey(kidOrThumb, iss string) (PublicKey, error) {
	now := time.Now()
	key, ok := hasPublicKeyByThumbprint(kidOrThumb)

	if !ok {
		key, ok = hasPublicKey(kidOrThumb, iss)
		if !ok {
			return FetchOIDCPublicKey(kidOrThumb, iss)
		}
	}

	// Fetch just a little before the key actually expires
	if key.Expiry.Sub(now) <= StaleTime {
		go FetchOIDCPublicKey(kidOrThumb, iss)
	}

	return key.Key, nil
}

var cacheKey = func(kid, iss, expstr string, pub PublicKey) error {
	var expiry time.Time

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

	// Put the key in the cache by both kid and thumbprint, and set the expiry
	KeyCacheMux.Lock()
	id := kid + "@" + iss
	KeyCache[id] = CachableKey{
		Key:    pub,
		Expiry: expiry,
	}
	thumb := pub.Thumbprint()
	id = thumb + "@" + iss
	KeyCache[id] = CachableKey{
		Key:    pub,
		Expiry: expiry,
	}
	// Since thumbprints are crypto secure, iss is not strictly needed
	KeyCache[thumb] = CachableKey{
		Key:    pub,
		Expiry: expiry,
	}
	KeyCacheMux.Unlock()

	return nil
}

func cacheKeys(maps map[string]map[string]string, keys map[string]PublicKey, issuer string) {
	for i := range keys {
		key := keys[i]
		m := maps[i]
		if "" != m["iss"] {
			issuer = m["iss"]
		}
		cacheKey(m["kid"], strings.TrimRight(issuer, "/"), m["exp"], key)
	}
}

func getStringMap(m map[string]interface{}) map[string]string {
	n := make(map[string]string)

	// TODO get issuer from x5c, if exists

	// convert map[string]interface{} to map[string]string
	for j := range m {
		switch s := m[j].(type) {
		case string:
			n[j] = s
		default:
			// safely ignore
		}
	}

	return n
}

type decodeFunc func(io.Reader) error

// TODO: also limit the body size
func safeFetch(url string, decoder decodeFunc) error {
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	var netClient = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

	res, err := netClient.Get(url)
	if nil != err {
		return err
	}
	defer res.Body.Close()

	return decoder(res.Body)
}
