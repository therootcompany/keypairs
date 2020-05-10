# go-keypairs

JSON Web Key (JWK) support and type safety lightly placed over top of Go's `crypto/ecdsa` and `crypto/rsa`

Useful for JWT, JOSE, etc.

```go
key, err := keypairs.ParsePrivateKey(bytesForJWKOrPEMOrDER)

pub, err := keypairs.ParsePublicKey(bytesForJWKOrPEMOrDER)

jwk, err := keypairs.MarshalJWKPublicKey(pub, time.Now().Add(2 * time.Day))

kid, err := keypairs.ThumbprintPublicKey(pub)
```

# API Documentation

See <https://pkg.go.dev/git.rootprojects.org/root/keypairs>

# Philosophy

Go's standard library is great.

Go has _excellent_ crytography support and provides wonderful
primitives for dealing with them.

I prefer to stay as close to Go's `crypto` package as possible,
just adding a light touch for JWT support and type safety.

# Type Safety

`crypto.PublicKey` is a "marker interface", meaning that it is **not typesafe**!

`go-keypairs` defines `type keypairs.PrivateKey interface { Public() crypto.PublicKey }`,
which is implemented by `crypto/rsa` and `crypto/ecdsa`
(but not `crypto/dsa`, which we really don't care that much about).

Go1.15 will add `[PublicKey.Equal(crypto.PublicKey)](https://github.com/golang/go/issues/21704)`,
which will make it possible to remove the additional wrapper over `PublicKey`
and use an interface instead.

Since there are no common methods between `rsa.PublicKey` and `ecdsa.PublicKey`,
go-keypairs lightly wraps each to implement `Thumbprint() string` (part of the JOSE/JWK spec).

## JSON Web Key (JWK) as a "codec"

Although there are many, many ways that JWKs could be interpreted
(possibly why they haven't made it into the standard library), `go-keypairs`
follows the basic pattern of `encoding/x509` to `Parse` and `Marshal`
only the most basic and most meaningful parts of a key.

I highly recommend that you use `Thumbprint()` for `KeyID` you also
get the benefit of not losing information when encoding and decoding
between the ASN.1, x509, PEM, and JWK formats.

# LICENSE

Copyright (c) 2020-present AJ ONeal
Copyright (c) 2018-2019 Big Squid, Inc.

This work is licensed under the terms of the MIT license.
For a copy, see <https://opensource.org/licenses/MIT>.
