package keypairs

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var EInvalidPrivateKey = errors.New("PrivateKey must be of type rsa.PrivateKey or ecdsa.PrivateKey")
var EInvalidPublicKey = errors.New("PublicKey must be of type rsa.PublicKey or ecdsa.PublicKey")
var EParsePrivateKey = errors.New("PrivateKey bytes could not be parsed as PEM or DER (PKCS8, SEC1, or PKCS1) or JWK")
var EParseJWK = errors.New("JWK is missing required base64-encoded JSON fields")
var EInvalidKeyType = errors.New("The JWK's 'kty' must be either 'RSA' or 'EC'")
var EInvalidCurve = errors.New("The JWK's 'crv' must be either of the NIST standards 'P-256' or 'P-384'")

// PrivateKey acts as the missing would-be interface crypto.PrivateKey
type PrivateKey interface {
	Public() crypto.PublicKey
}

func MarshalPublicJWK(key crypto.PublicKey) []byte {
	// thumbprint keys are alphabetically sorted and only include the necessary public parts
	switch k := key.(type) {
	case *rsa.PublicKey:
		return MarshalRSAPublicKey(k)
	case *ecdsa.PublicKey:
		return MarshalECPublicKey(k)
	case *dsa.PublicKey:
		panic(EInvalidPublicKey)
	default:
		// this is unreachable because we know the types that we pass in
		panic(EInvalidPublicKey)
	}
}

func ThumbprintPublicKey(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		return ThumbprintECPublicKey(p)
	case *rsa.PublicKey:
		return ThumbprintRSAPublicKey(p)
	default:
		panic(EInvalidPublicKey)
	}
}

func MarshalECPublicKey(k *ecdsa.PublicKey) []byte {
	thumb := ThumbprintECPublicKey(k)
	crv := k.Curve.Params().Name
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	return []byte(fmt.Sprintf(`{"kid":%q,"crv":%q,"kty":"EC","x":%q,"y":%q}`, thumb, crv, x, y))
}

func MarshalECPublicKeyWithoutKeyID(k *ecdsa.PublicKey) []byte {
	crv := k.Curve.Params().Name
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	return []byte(fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y))
}

func ThumbprintECPublicKey(k *ecdsa.PublicKey) string {
	thumbprintable := MarshalECPublicKeyWithoutKeyID(k)
	sha := sha256.Sum256(thumbprintable)
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

func MarshalRSAPublicKey(p *rsa.PublicKey) []byte {
	thumb := ThumbprintRSAPublicKey(p)
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(p.N.Bytes())
	return []byte(fmt.Sprintf(`{"kid":%q,"e":%q,"kty":"RSA","n":%q}`, thumb, e, n))
}

func MarshalRSAPublicKeyWithoutKeyID(p *rsa.PublicKey) []byte {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(p.N.Bytes())
	return []byte(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n))
}

func ThumbprintRSAPublicKey(p *rsa.PublicKey) string {
	thumbprintable := MarshalRSAPublicKeyWithoutKeyID(p)
	sha := sha256.Sum256([]byte(thumbprintable))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

func ParsePrivateKey(block []byte) (PrivateKey, error) {
	var pemblock *pem.Block
	var blocks = make([][]byte, 0, 1)

	// Parse the PEM, if it's a pem
	for {
		pemblock, block = pem.Decode(block)
		if nil != pemblock {
			// got one block, there may be more
			blocks = append(blocks, pemblock.Bytes)
		} else {
			// the last block was not a PEM block
			// therefore the next isn't either
			if 0 != len(block) {
				blocks = append(blocks, block)
			}
			break
		}
	}

	// Parse PEM blocks (openssl generates junk metadata blocks for ECs)
	// or the original DER, or the JWK
	for i, _ := range blocks {
		block = blocks[i]
		if key, err := parsePrivateKey(block); nil == err {
			return key, nil
		}
	}

	// If we didn't parse a key arleady, we failed
	return nil, EParsePrivateKey
}

func parsePrivateKey(der []byte) (PrivateKey, error) {
	var key PrivateKey

	//fmt.Println("1. ParsePKCS8PrivateKey")
	xkey, err := x509.ParsePKCS8PrivateKey(der)
	if nil == err {
		switch k := xkey.(type) {
		case *rsa.PrivateKey:
			key = k
		case *ecdsa.PrivateKey:
			key = k
		default:
			// ignore nil and unknown key types
		}
	}

	if nil != err {
		//fmt.Println("2. ParseECPrivateKey")
		key, err = x509.ParseECPrivateKey(der)
		if nil != err {
			//fmt.Println("3. ParsePKCS1PrivateKey")
			key, err = x509.ParsePKCS1PrivateKey(der)
			if nil != err {
				//fmt.Println("4. ParseJWKPrivateKey")
				key, err = ParseJWKPrivateKey(der)
			}
		}
	}

	// But did you know?
	// You must return nil explicitly for interfaces
	// https://golang.org/doc/faq#nil_error
	if nil != err {
		return nil, err
	}

	return key, nil
}

func ParseJWKPublicKey(b []byte) (crypto.PublicKey, error) {
	m := make(map[string]string)
	err := json.Unmarshal(b, &m)
	if nil != err {
		return nil, err
	}

	switch m["kty"] {
	case "RSA":
		return parseRSAPublicKey(m)
	case "EC":
		return parseECPublicKey(m)
	default:
		err = EInvalidKeyType
	}

	return nil, err
}

func ParseJWKPrivateKey(b []byte) (PrivateKey, error) {
	var m map[string]string
	if err := json.Unmarshal(b, &m); nil != err {
		return nil, err
	}

	switch m["kty"] {
	case "RSA":
		return parseRSAPrivateKey(m)
	case "EC":
		return parseECPrivateKey(m)
	default:
		return nil, EInvalidKeyType
	}
}

func parseRSAPublicKey(m map[string]string) (pub *rsa.PublicKey, err error) {
	n, _ := base64.RawURLEncoding.DecodeString(m["n"])
	e, _ := base64.RawURLEncoding.DecodeString(m["e"])
	if 0 == len(n) || 0 == len(e) {
		err = EParseJWK
		return
	}
	ni := &big.Int{}
	ni.SetBytes(n)
	ei := &big.Int{}
	ei.SetBytes(e)

	pub = &rsa.PublicKey{
		N: ni,
		E: int(ei.Int64()),
	}
	return
}

func parseRSAPrivateKey(m map[string]string) (key *rsa.PrivateKey, err error) {
	var pub *rsa.PublicKey

	pub, err = parseRSAPublicKey(m)
	if nil != err {
		return
	}

	d, _ := base64.RawURLEncoding.DecodeString(m["d"])
	p, _ := base64.RawURLEncoding.DecodeString(m["p"])
	q, _ := base64.RawURLEncoding.DecodeString(m["q"])
	dp, _ := base64.RawURLEncoding.DecodeString(m["dp"])
	dq, _ := base64.RawURLEncoding.DecodeString(m["dq"])
	qinv, _ := base64.RawURLEncoding.DecodeString(m["qi"])
	if 0 == len(d) || 0 == len(p) || 0 == len(dp) || 0 == len(dq) || 0 == len(qinv) {
		return nil, EParseJWK
	}

	di := &big.Int{}
	di.SetBytes(d)
	pi := &big.Int{}
	pi.SetBytes(p)
	qi := &big.Int{}
	qi.SetBytes(q)
	dpi := &big.Int{}
	dpi.SetBytes(dp)
	dqi := &big.Int{}
	dqi.SetBytes(dq)
	qinvi := &big.Int{}
	qinvi.SetBytes(qinv)

	key = &rsa.PrivateKey{
		PublicKey: *pub,
		D:         di,
		Primes:    []*big.Int{pi, qi},
		Precomputed: rsa.PrecomputedValues{
			Dp:   dpi,
			Dq:   dqi,
			Qinv: qinvi,
		},
	}

	return
}

func parseECPublicKey(m map[string]string) (pub *ecdsa.PublicKey, err error) {
	x, _ := base64.RawURLEncoding.DecodeString(m["x"])
	y, _ := base64.RawURLEncoding.DecodeString(m["y"])
	if 0 == len(x) || 0 == len(y) || 0 == len(m["crv"]) {
		return nil, EParseJWK
	}

	xi := &big.Int{}
	xi.SetBytes(x)

	yi := &big.Int{}
	yi.SetBytes(y)

	var crv elliptic.Curve
	switch m["crv"] {
	case "P-256":
		crv = elliptic.P256()
	case "P-384":
		crv = elliptic.P384()
	case "P-521":
		crv = elliptic.P521()
	default:
		err = EInvalidCurve
		return
	}

	pub = &ecdsa.PublicKey{
		Curve: crv,
		X:     xi,
		Y:     yi,
	}

	return
}

func parseECPrivateKey(m map[string]string) (*ecdsa.PrivateKey, error) {
	pub, err := parseECPublicKey(m)
	if nil != err {
		return nil, err
	}

	d, _ := base64.RawURLEncoding.DecodeString(m["d"])
	if 0 == len(d) {
		return nil, EParseJWK
	}
	di := &big.Int{}
	di.SetBytes(d)

	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         di,
	}, nil
}
