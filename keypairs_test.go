package keypairs

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestLoadECJWK(t *testing.T) {
	// TODO package all fixtures with fileb0x
	keypaths := []string{
		"fixtures/privkey-ec-p256.jwk.json",
		"fixtures/privkey-ec-p256.sec1.pem", // has openssl EC Param block
		"fixtures/privkey-ec-p256.pkcs8.pem",
		"fixtures/privkey-ec-p384.jwk.json",
		"fixtures/privkey-ec-p384.sec1.pem",
		"fixtures/privkey-ec-p384.pkcs8.pem",
	}
	for i := range keypaths {
		path := keypaths[i]
		fmt.Println("\n", path)
		b, err := ioutil.ReadFile(path)
		if nil != err {
			t.Fatal(err)
		}

		key, err := ParsePrivateKey(b)
		if nil != err {
			t.Fatal(err)
		}

		eckey := key.(*ecdsa.PrivateKey)
		thumb := ThumbprintECPublicKey(eckey.Public().(*ecdsa.PublicKey))
		fmt.Println(thumb)
	}
}
