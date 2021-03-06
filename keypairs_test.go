package keypairs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

// TODO package all fixtures with fileb0x

func TestParsePrivateKeyEC(t *testing.T) {
	keys := [][]string{
		[]string{"fixtures/privkey-ec-p256.jwk.json", "bJiCcZHuAF9dDetKEdGjJU3pFvFLoB_QHe9_6cAuY8c"},
		// has openssl EC Param block
		[]string{"fixtures/privkey-ec-p256.sec1.pem", "bJiCcZHuAF9dDetKEdGjJU3pFvFLoB_QHe9_6cAuY8c"},
		[]string{"fixtures/privkey-ec-p256.pkcs8.pem", "bJiCcZHuAF9dDetKEdGjJU3pFvFLoB_QHe9_6cAuY8c"},

		[]string{"fixtures/privkey-ec-p384.jwk.json", "-WoRXrk3FZ7tGi8oj5wJHDDfFMBCGlUbpwil1WhpxrU"},
		[]string{"fixtures/privkey-ec-p384.sec1.pem", "-WoRXrk3FZ7tGi8oj5wJHDDfFMBCGlUbpwil1WhpxrU"},
		[]string{"fixtures/privkey-ec-p384.pkcs8.pem", "-WoRXrk3FZ7tGi8oj5wJHDDfFMBCGlUbpwil1WhpxrU"},
	}
	for i := range keys {
		path := keys[i][0]
		thumb := keys[i][1]
		b, err := ioutil.ReadFile(path)
		if nil != err {
			t.Fatal(path, err)
		}

		key, err := ParsePrivateKey(b)
		if nil != err {
			t.Fatal(path, err)
		}

		eckey := key.(*ecdsa.PrivateKey)
		thumb2 := ThumbprintECPublicKey(eckey.Public().(*ecdsa.PublicKey))
		if thumb != thumb2 {
			t.Fatalf("EC thumbprints do not match: %q, %q, %q", path, thumb, thumb2)
		}
	}
}

func TestParseUnexpectedPrivateKey(t *testing.T) {
	keypaths := []string{
		"fixtures/privkey-ec-p256.jwk.json",
		"fixtures/privkey-ec-p256.sec1.pem",
		"fixtures/privkey-ec-p256.pkcs8.pem",
		"fixtures/privkey-rsa-2048.jwk.json",
		"fixtures/privkey-rsa-2048.pkcs1.pem",
		"fixtures/privkey-rsa-2048.pkcs8.pem",
	}
	for i := range keypaths {
		path := keypaths[i]
		b, err := ioutil.ReadFile(path)
		if nil != err {
			t.Fatal(path, err)
		}

		_, err = ParsePublicKey(b)
		switch err {
		case ErrUnexpectedPrivateKey:
			continue
		default:
			t.Fatal(path, err)
		}
	}
}

func TestParseUnexpectedPublicKey(t *testing.T) {
	keypaths := []string{
		"fixtures/pub-ec-p256.jwk.json",
	}
	for i := range keypaths {
		path := keypaths[i]
		b, err := ioutil.ReadFile(path)
		if nil != err {
			t.Fatal(path, err)
		}

		_, err = ParsePrivateKey(b)
		switch err {
		case ErrUnexpectedPublicKey:
			continue
		default:
			t.Fatal(path, err)
		}
	}
}

func TestParsePrivateKeyRSA(t *testing.T) {
	keypaths := []string{
		"fixtures/privkey-rsa-2048.jwk.json",
		"fixtures/privkey-rsa-2048.pkcs1.pem",
		"fixtures/privkey-rsa-2048.pkcs8.pem",
	}
	for i := range keypaths {
		path := keypaths[i]
		b, err := ioutil.ReadFile(path)
		if nil != err {
			t.Fatal(path, err)
		}

		key, err := ParsePrivateKey(b)
		if nil != err {
			t.Fatal(path, err)
		}

		rsakey := key.(*rsa.PrivateKey)
		thumb := "UIyZzFXPL-mTLnxQeSAHgu7gV16tro3evksnFb8fFQQ"
		thumb2 := ThumbprintRSAPublicKey(rsakey.Public().(*rsa.PublicKey))
		if thumb != thumb2 {
			t.Fatalf("RSA thumbprints do not match: %q, %q, %q", path, thumb, thumb2)
		}
	}
}

func TestParseCertificate(t *testing.T) {
	resp, err := http.Get("https://example.auth0.com/pem")
	if nil != err {
		log.Fatal(err)
	}
	bytes, err := ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Fatal(err)
	}
	_, err = ParsePublicKey(bytes)
	if nil != err {
		log.Fatal("Could not parse PEM/cert from auth0")
		log.Fatal(err)
	}
}
