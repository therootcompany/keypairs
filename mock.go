package keypairs

import (
	"crypto/rsa"
	"io"
	"log"
	mathrand "math/rand"
)

// this shananigans is only for testing and debug API stuff
func (o *keyOptions) maybeMockReader() io.Reader {
	if !allowMocking {
		panic("mock method called when mocking is not allowed")
	}

	if 0 == o.mockSeed {
		return randReader
	}

	log.Println("WARNING: MOCK: using insecure reader")
	return mathrand.New(mathrand.NewSource(o.mockSeed))
}

const maxRetry = 16

func maybeDerandomizeMockKey(privkey PrivateKey, keylen int, opts *keyOptions) PrivateKey {
	if 0 != opts.mockSeed {
		for i := 0; i < maxRetry; i++ {
			otherkey, _ := rsa.GenerateKey(opts.nextReader(), keylen)
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

	return privkey
}
