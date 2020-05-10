// Package uncached provides uncached versions of go-keypairs/keyfetch
package uncached

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"git.rootprojects.org/root/keypairs"
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
	url := baseURL + ".well-known/jwks.json"

	return JWKs(url)
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

		key, err := keypairs.NewJWKPublicKey(m)

		if nil != err {
			return nil, nil, err
		}
		keys[key.Thumbprint()] = key
		maps[key.Thumbprint()] = m
	}

	return maps, keys, nil
}

// PEM fetches and parses a PEM (assuming well-known format)
func PEM(pemurl string) (map[string]string, keypairs.PublicKey, error) {
	var pub keypairs.PublicKey
	if err := safeFetch(pemurl, func(body io.Reader) error {
		pem, err := ioutil.ReadAll(body)
		if nil != err {
			return err
		}
		pub, err = keypairs.ParsePublicKey(pem)
		return err
	}); nil != err {
		return nil, nil, err
	}

	jwk := map[string]interface{}{}
	body := bytes.NewBuffer(keypairs.MarshalJWKPublicKey(pub))
	decoder := json.NewDecoder(body)
	decoder.UseNumber()
	_ = decoder.Decode(&jwk)

	m := getStringMap(jwk)
	m["kid"] = pemurl

	switch p := pub.(type) {
	case *keypairs.ECPublicKey:
		p.KID = pemurl
	case *keypairs.RSAPublicKey:
		p.KID = pemurl
	default:
		return nil, nil, errors.New("impossible key type")
	}

	return m, pub, nil
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
	var client = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "go-keypairs/keyfetch")
	req.Header.Set("Accept", "application/json;q=0.9,*/*;q=0.8")
	res, err := client.Do(req)
	if nil != err {
		return err
	}
	defer res.Body.Close()

	return decoder(res.Body)
}

func normalizeBaseURL(iss string) string {
	return strings.TrimRight(iss, "/") + "/"
}
