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
var maxRetry = 1

// KeyOptions are the things that we may need to know about a request to fulfill it properly
type keyOptions struct {
	//Key     string `json:"key"`
	KeyType string `json:"kty"`
	//Seed    int64  `json:"-"`
	//SeedStr string `json:"seed"`
	//Claims  Object `json:"claims"`
	//Header  Object `json:"header"`
}

// this shananigans is only for testing and debug API stuff
func (o *keyOptions) myFooNextReader() io.Reader {
	return randReader
	/*
		if 0 == o.Seed {
			return randReader
		}
		return mathrand.New(mathrand.NewSource(o.Seed))
	*/
}

// NewDefaultPrivateKey generates a key with reasonable strength.
// Today that means a 256-bit equivalent - either RSA 2048 or EC P-256.
func NewDefaultPrivateKey() PrivateKey {
	mathrand.Seed(time.Now().UnixNano())
	coin := mathrand.Int()
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
		privkey, _ = rsa.GenerateKey(opts.myFooNextReader(), keylen)
		/*
			if 0 != opts.Seed {
				for i := 0; i < maxRetry; i++ {
					otherkey, _ := rsa.GenerateKey(opts.myFooNextReader(), keylen)
					otherCmp := otherkey.D.Cmp(privkey.(*rsa.PrivateKey).D)
					if 0 != otherCmp {
						// There are two possible keys, choose the lesser D value
						// See https://github.com/square/go-jose/issues/189
						if otherCmp < 0 {
							privkey = otherkey
						}
						break
					}
					if maxRetry == i-1 {
						log.Printf("error: coinflip landed on heads %d times", maxRetry)
					}
				}
			}
		*/
	} else {
		// TODO: EC keys may also suffer the same random problems in the future
		privkey, _ = ecdsa.GenerateKey(elliptic.P256(), opts.myFooNextReader())
	}
	return privkey
}
