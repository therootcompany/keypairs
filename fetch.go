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

func FetchOIDCPublicKeys(host string) ([]crypto.PublicKey, error) {
	oidcConf := struct {
		JWKSURI string `json:"jwks_uri"`
	}{}
	// must come in as https://<domain>/
	url := host + ".well-known/openid-configuration"
	err := safeFetch(url, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&oidcConf)
	})
	if nil != err {
		return nil, err
	}

	return FetchPublicKeys(oidcConf.JWKSURI)
}

func FetchPublicKeys(jwksurl string) ([]crypto.PublicKey, error) {
	var keys []crypto.PublicKey
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
			keys = append(keys, key)
		}
	}

	return keys, nil
}

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
