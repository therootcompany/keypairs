# go-keypairs

The lightest touch over top of Go's `crypto/ecdsa` and `crypto/rsa` to make them
*typesafe* and to provide JSON Web Key (JWK) support.

# Documentation

Use the source, Luke!

<https://godoc.org/github.com/big-squid/go-keypairs>

# Philosophy

Always remember:

> Don't roll your own crypto.

But also remember:

> Just because you _don't_ know someone doesn't make them smart.

Don't get the two mixed up!

(furthermore, [just because you _do_ know someone doesn't make them _not_ smart](https://www.humancondition.com/asid-prophets-without-honour-in-their-own-home/))

Although I would **not** want to invent my own cryptographic algorithm,
I've read enough source code to know that, for standards I know well,
I feel much more confident in the security, extensibility, and documentation
of tooling that I've write myself.

# Type Safety

Go has _excellent_ crytography support and provides wonderful
primitives for dealing with them. Its Achilles' heel is they're **not typesafe**!

As of Go 1.11.5 `crypto.PublicKey` and `crypto.PrivateKey` are "marker interfaces"
or, in other words, empty interfaces that only serve to document intent without
actually providing a constraint to the type system.

go-keypairs defines `type keypairs.PrivateKey interface { Public() crypto.PublicKey }`,
which is implemented by `crypto/rsa` and `crypto/ecdsa`
(but not `crypto/dsa`, which we really don't care that much about).

Since there are no common methods between `rsa.PublicKey` and `ecdsa.PublicKey`,
go-keypairs lightly wraps each to implement `Thumbprint() string` (part of the JOSE/JWK spec).

# JSON Web Key "codec"

Although there are many, many ways that JWKs could be interpreted
(possibly why they haven't made it into the standard library), go-keypairs
follows the basic pattern of `encoding/x509` to Parse and Marshal
only the most basic and most meaningful parts of a key.

I highly recommend that you use `Thumbprint()` for `KeyID` you also
get the benefit of not losing information when encoding and decoding
between the ASN.1, x509, PEM, and JWK formats.

# LICENSE

Copyright (c) 2018-2019 Big Squid, Inc.

This work is licensed under the terms of the MIT license.
For a copy, see <https://opensource.org/licenses/MIT>.
