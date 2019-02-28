package keydist

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	keypairs "github.com/big-squid/go-keypairs"
)

// DefaultExpiresIn is 3 days
var DefaultExpiresIn = 72 * time.Hour

// JWKsPath is "/.well-known/jwks.json" (Auth0 spec)
const JWKsPath = "/.well-known/jwks.json"

// jwksURL is ".well-known/jwks.json" (Auth0 spec)
var jwksURL, _ = url.Parse(".well-known/jwks.json")

// OIDCPath is "/.well-known/openid-configuration" (OIDC spec)
const OIDCPath = "/.well-known/openid-configuration"

// oidcURL is ".well-known/openid-configuration" (OIDC spec)
var oidcURL, _ = url.Parse(".well-known/openid-configuration")

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

// Handler
func (m *Middleware) Handler(w http.ResponseWriter, r *http.Request) bool {

	if strings.HasSuffix(r.URL.Path, jwksURL.Path) {
		m.WellKnownJWKs(w, r)
		return true
	}

	if strings.HasSuffix(r.URL.Path, oidcURL.Path) {
		m.WellKnownOIDC(w, r)
		return true
	}

	return false
}

// WellKnownOIDC serves a minimal OIDC config for the purpose of distributing JWKs
// if you need something more powerful, do it yourself.
// (but feel free to copy the code here)
func (m *Middleware) WellKnownOIDC(w http.ResponseWriter, r *http.Request) {
	var baseURL url.URL

	// Use a defined BaseURL, or an implicit one
	if nil != m.BaseURL {
		baseURL = *m.BaseURL
	} else {
		baseURL = *r.URL
		baseURL.Host = r.Host
		baseURL.Path = strings.TrimSuffix(baseURL.Path, oidcURL.Path)
	}

	// avoiding with correctly handling trailing vs non-trailing '/'
	u := baseURL.ResolveReference(jwksURL)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{ "issuer": %q, "jwks_uri": %q }`, baseURL, u)))
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
