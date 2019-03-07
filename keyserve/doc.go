/*

Package keyserve provides middleware to serve Public Keys
via OIDC-style (https://example.com/.well-known/openid-configuration)
and Auth0-style (https://example.com/.well-known/jwks.json)
URLs. It uses the keypairs package to encode to JWK format.

Basic Usage

	import (
		"crypto/ecdsa"
		"crypto/rand"
		"time"

		"github.com/big-squid/go-keypairs/keyserve"
	)

	key, _ := ecdsa.GenerateKey(elliptic.P256, rand.Reader)
	pub := key.Public()

	handlers := &keyserve.Middleware{

		// the self-reference used for building the openid-configuration url
		BaseURL: "https://example.com/",

		// public keys used to verify token signatures
		Keys: []keypairs.PublicKey{ keypairs.NewPublicKey(pub) }

		// how long clients should cache your public key
		ExpiresIn: 72 * time.Hour

	}

You can then use the handlers anywhere http.HandleFunc is allowed:

	http.HandleFunc(keyserve.PEMPath, handlers.Auth0PEM)
	http.HandleFunc(keyserve.JWKsPath, handlers.WellKnownJWKs)
	http.HandleFunc(keyserve.OIDCPath, handlers.WellKnownOIDC)

*/
package keyserve
