/*
Package keypairs complements Go's standard keypair-related packages
(encoding/pem, crypto/x509, crypto/rsa, crypto/ecdsa, crypto/elliptic)
with JWK encoding support and typesafe PrivateKey and PublicKey interfaces.

Basics

	key, err := keypairs.ParsePrivateKey(bytesForJWKOrPEMOrDER)

	pub, err := keypairs.ParsePublicKey(bytesForJWKOrPEMOrDER)

	jwk, err := keypairs.MarshalJWKPublicKey(pub, time.Now().Add(2 * time.Day))

	kid, err := keypairs.ThumbprintPublicKey(pub)

Convenience functions are available which will fetch keys
(or retrieve them from cache) via OIDC, .well-known/jwks.json, and direct urls.
All keys are cached by Thumbprint, as well as kid(@issuer), if available.

	import "git.rootprojects.org/root/keypairs/keyfetch"

	pubs, err := keyfetch.OIDCJWKs("https://example.com/")
	pubs, err := keyfetch.OIDCJWK(ThumbOrKeyID, "https://example.com/")

	pubs, err := keyfetch.WellKnownJWKs("https://example.com/")
	pubs, err := keyfetch.WellKnownJWK(ThumbOrKeyID, "https://example.com/")

	pubs, err := keyfetch.JWKs("https://example.com/path/to/jwks/")
	pubs, err := keyfetch.JWK(ThumbOrKeyID, "https://example.com/path/to/jwks/")

	// From URL
	pub, err := keyfetch.Fetch("https://example.com/jwk.json")

	// From Cache only
	pub := keyfetch.Get(thumbprint, "https://example.com/jwk.json")

A non-caching version with the same capabilities is also available.

*/
package keypairs
