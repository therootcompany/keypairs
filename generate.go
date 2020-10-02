package keypairs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	mathrand "math/rand"
	"time"
)

var randReader io.Reader = rand.Reader
var allowMocking = false

// KeyOptions are the things that we may need to know about a request to fulfill it properly
type keyOptions struct {
	//Key     string `json:"key"`
	KeyType  string `json:"kty"`
	mockSeed int64  //`json:"-"`
	//SeedStr string `json:"seed"`
	//Claims  Object `json:"claims"`
	//Header  Object `json:"header"`
}

func (o *keyOptions) nextReader() io.Reader {
	if allowMocking {
		return o.maybeMockReader()
	}
	return randReader
}

// NewDefaultPrivateKey generates a key with reasonable strength.
// Today that means a 256-bit equivalent - either RSA 2048 or EC P-256.
func NewDefaultPrivateKey() PrivateKey {
	// insecure random is okay here,
	// it's just used for a coin toss
	mathrand.Seed(time.Now().UnixNano())
	coin := mathrand.Int()

	// the idea here is that we want to make
	// it dead simple to support RSA and EC
	// so it shouldn't matter which is used
	if 0 == coin%2 {
		return newPrivateKey(&keyOptions{
			KeyType: "RSA",
		})
	}
	return newPrivateKey(&keyOptions{
		KeyType: "EC",
	})
}

// newPrivateKey generates a 256-bit entropy RSA or ECDSA private key
func newPrivateKey(opts *keyOptions) PrivateKey {
	var privkey PrivateKey

	if "RSA" == opts.KeyType {
		keylen := 2048
		privkey, _ = rsa.GenerateKey(opts.nextReader(), keylen)
		if allowMocking {
			privkey = maybeDerandomizeMockKey(privkey, keylen, opts)
		}
	} else {
		// TODO: EC keys may also suffer the same random problems in the future
		privkey, _ = ecdsa.GenerateKey(elliptic.P256(), opts.nextReader())
	}
	return privkey
}
