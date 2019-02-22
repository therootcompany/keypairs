// Package uncached provides uncached versions of go-keypairs/keyfetch
package uncached

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	keypairs "github.com/big-squid/go-keypairs"
)

// OIDCJWKs gets the OpenID Connect configuration from the baseURL and then calls JWKs with the specified jwks_uri
func OIDCJWKs(baseURL string) (map[string]map[string]string, map[string]keypairs.PublicKey, error) {
	baseURL = normalizeBaseURL(baseURL)
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

	return JWKs(oidcConf.JWKSURI)
}

// WellKnownJWKs calls JWKs with baseURL + /.well-known/jwks.json as constructs the jwks_uri
func WellKnownJWKs(baseURL string) (map[string]map[string]string, map[string]keypairs.PublicKey, error) {
	baseURL = normalizeBaseURL(baseURL)
	if '/' == baseURL[len(baseURL)-1] {
		baseURL = baseURL[:len(baseURL)-1]
	}

	return JWKs(baseURL + "/.well-known/jwks.json")
}

// JWKs fetches and parses a jwks.json (assuming well-known format)
func JWKs(jwksurl string) (map[string]map[string]string, map[string]keypairs.PublicKey, error) {
	keys := map[string]keypairs.PublicKey{}
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

		if key, err := keypairs.NewJWKPublicKey(m); nil != err {
			return nil, nil, err
		} else {
			keys[key.Thumbprint()] = key
			maps[key.Thumbprint()] = m
		}
	}

	return maps, keys, nil
}

// Fetch retrieves a single JWK (plain, bare jwk) from a URL (off-spec)
func Fetch(url string) (map[string]string, keypairs.PublicKey, error) {
	var m map[string]interface{}
	if err := safeFetch(url, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		decoder.UseNumber()
		return decoder.Decode(&m)
	}); nil != err {
		return nil, nil, err
	}

	n := getStringMap(m)
	key, err := keypairs.NewJWKPublicKey(n)
	if nil != err {
		return nil, nil, err
	}

	return n, key, nil
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

func normalizeBaseURL(iss string) string {
	return strings.TrimRight(iss, "/") + "/"
}
