package keyserve

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"git.rootprojects.org/root/keypairs"
)

// DefaultExpiresIn is 3 days
var DefaultExpiresIn = 72 * time.Hour

// JWKsPath is "/.well-known/jwks.json" (Auth0 spec)
const JWKsPath = "/.well-known/jwks.json"

var jwksURL, _ = url.Parse(".well-known/jwks.json")

// OIDCPath is "/.well-known/openid-configuration" (OIDC spec)
const OIDCPath = "/.well-known/openid-configuration"

var oidcURL, _ = url.Parse(".well-known/openid-configuration")

// PEMPath is "/pem" (Auth0 convention)
const PEMPath = "/pem"

var auth0PEMURL, _ = url.Parse("pem")

// for convenience
var notime time.Duration
var never = time.Time{}

// Middleware holds your public keys and has http handler methods for OIDC and Auth0 JWKs
type Middleware struct {
	BaseURL   *url.URL
	Keys      []keypairs.PublicKey
	ExpiresIn time.Duration
}

// General Note:
// Some frameworks don't properly handle the trailing ;charset=utf-8
// for Content-Type, and it doesn't add practical benefit, so we omit it
// (JSON _is_ utf-8, per spec, already).

// Handler will match either OIDC or Auth0 jwks URLs and return true if it
// matches on (and responds to) either. Otherwise it will return false.
func (m *Middleware) Handler(w http.ResponseWriter, r *http.Request) bool {

	if strings.HasSuffix(r.URL.Path, JWKsPath) {
		m.WellKnownJWKs(w, r)
		return true
	}

	if strings.HasSuffix(r.URL.Path, OIDCPath) {
		m.WellKnownOIDC(w, r)
		return true
	}

	if strings.HasSuffix(r.URL.Path, PEMPath) {
		m.Auth0PEM(w, r)
		return true
	}

	return false
}

// WellKnownOIDC serves a minimal OIDC config for the purpose of distributing
// JWKs if you need something more powerful, do it yourself.
// (but feel free to copy the code here)
//
// Security Note: If you do not supply Middleware.BaseURL, it will be taken
// from r.Host (since Web Browsers will always present it as the domain being
// accessed, which is not the case with TLS.ServerName over HTTP/2).
// This is normally not a problem because an attacker can only spoof back to
// themselves the jwks_uri. HOWEVER (DANGER, DANGER WILL ROBINSON) - RED FLAG -
// somewhere in the universe there is surely some old janky podunk proxy, still
// in use today, which is vulnerable to basic cache poisening which could cause
// others to receive a cached version of the malicious response rather than
// hitting the server and getting the correct response. Unlikely that that's
// you (and if it is you have much bigger problems), but I feel the need to
// warn you all the same - so just be sure to specify BaseURL.
func (m *Middleware) WellKnownOIDC(w http.ResponseWriter, r *http.Request) {
	var baseURL url.URL

	// Use a defined BaseURL, or an implicit one
	if nil != m.BaseURL {
		baseURL = *m.BaseURL
	} else {
		baseURL = *r.URL
		if nil == r.TLS && "https" != r.Header.Get("X-Forwarded-Proto") {
			baseURL.Scheme = "http"
		} else {
			baseURL.Scheme = "https"
		}
		baseURL.Host = r.Host
		baseURL.Path = strings.TrimSuffix(baseURL.Path, oidcURL.Path)
	}

	// avoiding with correctly handling trailing vs non-trailing '/'
	u := baseURL.ResolveReference(jwksURL)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{ "issuer": %q, "jwks_uri": %q }`, baseURL.String(), u.String())))
}

// WellKnownJWKs serves a JSON array of keys, no fluff
func (m *Middleware) WellKnownJWKs(w http.ResponseWriter, r *http.Request) {
	// Use either the user-supplied key expiration or our own default
	s := m.ExpiresIn
	if notime == s {
		s = DefaultExpiresIn
	}
	exp := time.Now().Add(s)

	jwks := marshalJWKs(m.Keys, exp)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"keys":[%s]}`, strings.Join(jwks, ","))))
}

// Auth0PEM serves a PEM containing a public key
func (m *Middleware) Auth0PEM(w http.ResponseWriter, r *http.Request) {
	// TODO serve a self-signed root certificate (like Auth0),
	// with a proper expiration date, instead
	w.Header().Set("Content-Type", "application/x-pem-file")

	switch pub := m.Keys[0].Key().(type) {
	case *rsa.PublicKey:
		pem.Encode(w, &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		})
	case *ecdsa.PublicKey:
		// skip error since we're type safe already
		bytes, _ := x509.MarshalPKIXPublicKey(pub)
		pem.Encode(w, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		})
	default:
		w.Write([]byte("Sanity Error: Impossible key type"))
	}
}

func marshalJWKs(keys []keypairs.PublicKey, exp2 time.Time) []string {
	jwks := make([]string, 0, 1)

	for i := range keys {
		key := keys[i]

		// if the key itself has an expiry, let that override
		exp := key.ExpiresAt()
		if never == exp {
			// otherwise use our default
			exp = exp2
		}

		// Note that you don't have to embed `iss` in the JWK because the client
		// already has that info by virtue of getting to it in the first place.
		jwk := string(keypairs.MarshalJWKPublicKey(key, exp))
		jwks = append(jwks, jwk)
	}

	return jwks
}
