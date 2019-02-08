package keypairs

import (
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

var EInvalidJWKURL = errors.New("url does not lead to valid JWKs")

// FetchOIDCPublicKeys fetches baseURL + ".well-known/openid-configuration" and then returns FetchPublicKeys(jwks_uri).
func FetchOIDCPublicKeys(baseURL string) (map[string]PublicKey, error) {
	oidcConf := struct {
		JWKSURI string `json:"jwks_uri"`
	}{}
	// must come in as https://<domain>/
	url := baseURL + ".well-known/openid-configuration"
	err := safeFetch(url, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&oidcConf)
	})
	if nil != err {
		return nil, err
	}

	return FetchPublicKeys(oidcConf.JWKSURI)
}

// FetchPublicKeys returns a map of keys identified by their kid or thumbprint (if kid is not specified)
func FetchPublicKeys(jwksurl string) (map[string]PublicKey, error) {
	keys := map[string]PublicKey{}
	resp := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: make([]map[string]interface{}, 0, 1),
	}

	if err := safeFetch(jwksurl, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&resp)
	}); nil != err {
		return nil, err
	}

	for i := range resp.Keys {
		n := map[string]string{}
		k := resp.Keys[i]

		// convert map[string]interface{} to map[string]string
		for j := range k {
			switch s := k[j].(type) {
			case string:
				n[j] = s
			default:
				// safely ignore
			}
		}

		if key, err := NewJWKPublicKey(n); nil != err {
			return nil, err
		} else {
			keys[key.Thumbprint()] = key
		}
	}

	return keys, nil
}

// FetchPublicKey retrieves a JWK from a URL that specifies only one
func FetchPublicKey(url string) (crypto.PublicKey, error) {
	var m map[string]string
	if err := safeFetch(url, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&m)
	}); nil != err {
		return nil, err
	}

	return NewJWKPublicKey(m)
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
