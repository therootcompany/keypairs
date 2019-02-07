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

const (
	Private KeyPrivacy = 1 << iota
	Public
)

const (
	EC KeyType = 1 << iota
	RSA
)

type KeyType uint
type KeyPrivacy uint

// PrivateKey acts as the missing would-be interface crypto.PrivateKey
type PrivateKey interface {
	Public() crypto.PublicKey
}

// JWK is to be used where either a public or private key may exist
type Key interface {
	Privacy() KeyPrivacy
	Type() KeyType
}

type PublicJWK struct {
	// TODO PEM Fingerprint
	//BareJWK    string `json:"-"`
	thumbprint thumbstr `json:"thumbprint"`
	jwk        jwkstr   `json:"jwk"`
}

func (p *PublicJWK) Thumbprint() string {
	return string(p.thumbprint)
}
func (p *PublicJWK) JWK() string {
	return string(p.jwk)
}

type thumbstr string
type jwkstr string

func FromPublic(key crypto.PublicKey) (pub PublicJWK) {
	// thumbprint keys are alphabetically sorted and only include the necessary public parts
	switch k := key.(type) {
	case *rsa.PublicKey:
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		thumbprintable := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
		sha := sha256.Sum256([]byte(thumbprintable))
		pub.thumbprint = thumbstr(base64.RawURLEncoding.EncodeToString(sha[:]))
		pub.jwk = jwkstr(fmt.Sprintf(`{"kid":%q,"e":%q,"kty":"RSA","n":%q}`, pub.Thumbprint(), e, n))
	case *ecdsa.PublicKey:
		x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
		thumbprintable := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Curve, x, y)
		sha := sha256.Sum256([]byte(thumbprintable))
		pub.thumbprint = thumbstr(base64.RawURLEncoding.EncodeToString(sha[:]))
		pub.jwk = jwkstr(fmt.Sprintf(`{"kid":%q,"crv":%q,"kty":"EC","x":%q,"y":%q}`, pub.Thumbprint(), k.Curve, x, y))
	case *dsa.PublicKey:
		panic(EInvalidPublicKey)
	default:
		// this is unreachable because we know the types that we pass in
		panic(EInvalidPublicKey)
	}

	return
}

var EInvalidPrivateKey = errors.New("PrivateKey must be of type rsa.PrivateKey or ecdsa.PrivateKey")
var EInvalidPublicKey = errors.New("PublicKey must be of type rsa.PublicKey or ecdsa.PublicKey")
var EParsePrivateKey = errors.New("PrivateKey bytes could not be parsed as PEM or DER (PKCS8, SEC1, or PKCS1) or JWK")
var EParseJWK = errors.New("JWK is missing required base64-encoded JSON fields")
var EInvalidKeyType = errors.New("The JWK's 'kty' must be either 'RSA' or 'EC'")
var EInvalidCurve = errors.New("The JWK's 'crv' must be either of the NIST standards 'P-256' or 'P-384'")

func ParsePrivateKey(block []byte) (key PrivateKey, err error) {
	var pemblock *pem.Block
	var blocks [][]byte = make([][]byte, 1)

	// Parse the PEM, if it's a pem
	for {
		pemblock, block = pem.Decode(block)
		if nil != pemblock {
			// got one block, there may be more
			blocks = append(blocks, pemblock.Bytes)
		} else {
			// the leftovers are not PEM blocks
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
		if key = parsePrivateKey(block); nil != key {
			return
		}
	}

	// If we didn't parse a key arleady, we failed
	err = EParsePrivateKey
	return
}

func parsePrivateKey(der []byte) (key PrivateKey) {
	xkey, _ := x509.ParsePKCS8PrivateKey(der)
	switch k := xkey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		// ignore nil and unknown key types
	}

	key = xkey.(*rsa.PrivateKey)
	if nil == key {
		key, _ = x509.ParseECPrivateKey(der)
		if nil == key {
			key, _ = x509.ParsePKCS1PrivateKey(der)
			if nil == key {
				key, _ = ParseJWKPrivateKey(der)
			}
		}
	}
	return
}

func ParseJWKPrivateKey(b []byte) (key PrivateKey, err error) {
	var m map[string]string
	err = json.Unmarshal(b, &m)
	if nil != err {
		return
	}

	switch m["kty"] {
	case "RSA":
		key, err = parsePrivateRSAJWK(m)
	case "EC":
		key, err = parsePrivateECJWK(m)
	default:
		err = EInvalidKeyType
	}

	return
}

func parsePrivateRSAJWK(m map[string]string) (key *rsa.PrivateKey, err error) {
	n, _ := base64.RawURLEncoding.DecodeString(m["n"])
	e, _ := base64.RawURLEncoding.DecodeString(m["e"])
	if 0 == len(n) || 0 == len(e) {
		return nil, EParseJWK
	}
	ni := &big.Int{}
	ni.SetBytes(n)
	ei := &big.Int{}
	ei.SetBytes(e)

	pub := rsa.PublicKey{
		N: ni,
		E: int(ei.Int64()),
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
		PublicKey: pub,
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

func parsePrivateECJWK(m map[string]string) (key *ecdsa.PrivateKey, err error) {
	x, _ := base64.RawURLEncoding.DecodeString(m["n"])
	y, _ := base64.RawURLEncoding.DecodeString(m["e"])
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

	pub := ecdsa.PublicKey{
		Curve: crv,
		X:     xi,
		Y:     yi,
	}

	d, _ := base64.RawURLEncoding.DecodeString(m["d"])
	if 0 == len(d) {
		return nil, EParseJWK
	}
	di := &big.Int{}
	di.SetBytes(d)

	key = &ecdsa.PrivateKey{
		PublicKey: pub,
		D:         di,
	}

	return
}
