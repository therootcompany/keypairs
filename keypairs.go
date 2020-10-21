package keypairs

import (
	"bytes"
	"crypto"
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
	"io"
	"log"
	"math/big"
	"strings"
	"time"
)

// ErrInvalidPrivateKey means that the key is not a valid Private Key
var ErrInvalidPrivateKey = errors.New("PrivateKey must be of type *rsa.PrivateKey or *ecdsa.PrivateKey")

// ErrInvalidPublicKey means that the key is not a valid Public Key
var ErrInvalidPublicKey = errors.New("PublicKey must be of type *rsa.PublicKey or *ecdsa.PublicKey")

// ErrParsePublicKey means that the bytes cannot be parsed in any known format
var ErrParsePublicKey = errors.New("PublicKey bytes could not be parsed as PEM or DER (PKIX/SPKI, PKCS1, or X509 Certificate) or JWK")

// ErrParsePrivateKey means that the bytes cannot be parsed in any known format
var ErrParsePrivateKey = errors.New("PrivateKey bytes could not be parsed as PEM or DER (PKCS8, SEC1, or PKCS1) or JWK")

// ErrParseJWK means that the JWK is valid JSON but not a valid JWK
var ErrParseJWK = errors.New("JWK is missing required base64-encoded JSON fields")

// ErrInvalidKeyType means that the key is not an acceptable type
var ErrInvalidKeyType = errors.New("The JWK's 'kty' must be either 'RSA' or 'EC'")

// ErrInvalidCurve means that a non-standard curve was used
var ErrInvalidCurve = errors.New("The JWK's 'crv' must be either of the NIST standards 'P-256' or 'P-384'")

// ErrUnexpectedPublicKey means that a Private Key was expected
var ErrUnexpectedPublicKey = errors.New("PrivateKey was given where PublicKey was expected")

// ErrUnexpectedPrivateKey means that a Public Key was expected
var ErrUnexpectedPrivateKey = errors.New("PublicKey was given where PrivateKey was expected")

// ErrDevSwapPrivatePublic means that the developer compiled bad code that swapped public and private keys
const ErrDevSwapPrivatePublic = "[Developer Error] You passed either crypto.PrivateKey or crypto.PublicKey where the other was expected."

// ErrDevBadKeyType means that the developer compiled bad code that passes the wrong type
const ErrDevBadKeyType = "[Developer Error] crypto.PublicKey and crypto.PrivateKey are somewhat deceptive. They're actually empty interfaces that accept any object, even non-crypto objects. You passed an object of type '%T' by mistake."

// PrivateKey is a zero-cost typesafe substitue for crypto.PrivateKey
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// PublicKey is so that v0.7.x can use golang v1.15 keys
type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// PublicKeyDeprecated thinly veils crypto.PublicKey for type safety
type PublicKeyDeprecated interface {
	crypto.PublicKey
	//Equal(x crypto.PublicKey) bool
	//Thumbprint() string
	KeyID() string
	Key() PublicKey
	ExpiresAt() time.Time
}

// ECPublicKey adds common methods to *ecdsa.PublicKey for type safety
type ECPublicKey struct {
	PublicKey *ecdsa.PublicKey // empty interface
	KID       string
	Expiry    time.Time
}

// RSAPublicKey adds common methods to *rsa.PublicKey for type safety
type RSAPublicKey struct {
	PublicKey *rsa.PublicKey // empty interface
	KID       string
	Expiry    time.Time
}

// Thumbprint returns a JWK thumbprint. See https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk
func (p *ECPublicKey) Thumbprint() string {
	return ThumbprintUntypedPublicKey(p.PublicKey)
}

// Equal returns true if the public key is equal.
func (p *ECPublicKey) Equal(x crypto.PublicKey) bool {
	return p.PublicKey.Equal(x)
}

// KeyID returns the JWK `kid`, which will be the Thumbprint for keys generated with this library
func (p *ECPublicKey) KeyID() string {
	return p.KID
}

// Key returns the PublicKey
func (p *ECPublicKey) Key() PublicKey {
	return p.PublicKey
}

// ExpireAt sets the time at which this Public Key should be considered invalid
func (p *ECPublicKey) ExpireAt(t time.Time) {
	p.Expiry = t
}

// ExpiresAt gets the time at which this Public Key should be considered invalid
func (p *ECPublicKey) ExpiresAt() time.Time {
	return p.Expiry
}

// Thumbprint returns a JWK thumbprint. See https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk
func (p *RSAPublicKey) Thumbprint() string {
	return ThumbprintUntypedPublicKey(p.PublicKey)
}

// Equal returns true if the public key is equal.
func (p *RSAPublicKey) Equal(x crypto.PublicKey) bool {
	return p.PublicKey.Equal(x)
}

// KeyID returns the JWK `kid`, which will be the Thumbprint for keys generated with this library
func (p *RSAPublicKey) KeyID() string {
	return p.KID
}

// Key returns the PublicKey
func (p *RSAPublicKey) Key() PublicKey {
	return p.PublicKey
}

// ExpireAt sets the time at which this Public Key should be considered invalid
func (p *RSAPublicKey) ExpireAt(t time.Time) {
	p.Expiry = t
}

// ExpiresAt gets the time at which this Public Key should be considered invalid
func (p *RSAPublicKey) ExpiresAt() time.Time {
	return p.Expiry
}

// NewPublicKey wraps a crypto.PublicKey to make it typesafe.
func NewPublicKey(pub crypto.PublicKey, kid ...string) PublicKeyDeprecated {
	_, ok := pub.(PublicKey)
	if !ok {
		panic("Developer Error: not a crypto.PublicKey")
	}

	var k PublicKeyDeprecated
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		eckey := &ECPublicKey{
			PublicKey: p,
		}
		if 0 != len(kid) {
			eckey.KID = kid[0]
		} else {
			eckey.KID = ThumbprintECPublicKey(p)
		}
		k = eckey
	case *rsa.PublicKey:
		rsakey := &RSAPublicKey{
			PublicKey: p,
		}
		if 0 != len(kid) {
			rsakey.KID = kid[0]
		} else {
			rsakey.KID = ThumbprintRSAPublicKey(p)
		}
		k = rsakey
	default:
		panic(fmt.Errorf(ErrDevBadKeyType, pub))
	}

	return k
}

// MarshalJWKPublicKey outputs a JWK with its key id (kid) and an optional expiration,
// making it suitable for use as an OIDC public key.
func MarshalJWKPublicKey(key PublicKey, exp ...time.Time) []byte {
	// thumbprint keys are alphabetically sorted and only include the necessary public parts
	switch k := key.(type) {
	case *rsa.PublicKey:
		return MarshalRSAPublicKey(k, exp...)
	case *ecdsa.PublicKey:
		return MarshalECPublicKey(k, exp...)
	default:
		// this is unreachable because we know the types that we pass in
		log.Printf("keytype: %t, %+v\n", key, key)
		panic(ErrInvalidPublicKey)
	}
}

// Thumbprint returns the SHA256 RFC-spec JWK thumbprint
func Thumbprint(pub PublicKey) string {
	return ThumbprintUntypedPublicKey(pub)
}

// ThumbprintPublicKey returns the SHA256 RFC-spec JWK thumbprint
func ThumbprintPublicKey(pub PublicKeyDeprecated) string {
	return ThumbprintUntypedPublicKey(pub.Key())
}

// ThumbprintUntypedPublicKey is a non-typesafe version of ThumbprintPublicKey
// (but will still panic, to help you discover bugs in development rather than production).
func ThumbprintUntypedPublicKey(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case PublicKeyDeprecated:
		return ThumbprintUntypedPublicKey(p.Key())
	case *ecdsa.PublicKey:
		return ThumbprintECPublicKey(p)
	case *rsa.PublicKey:
		return ThumbprintRSAPublicKey(p)
	default:
		panic(ErrInvalidPublicKey)
	}
}

// MarshalECPublicKey will take an EC key and output a JWK, with optional expiration date
func MarshalECPublicKey(k *ecdsa.PublicKey, exp ...time.Time) []byte {
	thumb := ThumbprintECPublicKey(k)
	crv := k.Curve.Params().Name
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	expstr := ""
	if 0 != len(exp) {
		expstr = fmt.Sprintf(`"exp":%d,`, exp[0].Unix())
	}
	return []byte(fmt.Sprintf(`{"kid":%q,"use":"sig",%s"crv":%q,"kty":"EC","x":%q,"y":%q}`, thumb, expstr, crv, x, y))
}

// MarshalECPublicKeyWithoutKeyID will output the most minimal version of an EC JWK (no key id, no "use" flag, nada)
func MarshalECPublicKeyWithoutKeyID(k *ecdsa.PublicKey) []byte {
	crv := k.Curve.Params().Name
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	return []byte(fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y))
}

// ThumbprintECPublicKey will output a RFC-spec SHA256 JWK thumbprint of an EC public key
func ThumbprintECPublicKey(k *ecdsa.PublicKey) string {
	thumbprintable := MarshalECPublicKeyWithoutKeyID(k)
	sha := sha256.Sum256(thumbprintable)
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// MarshalRSAPublicKey will take an RSA key and output a JWK, with optional expiration date
func MarshalRSAPublicKey(p *rsa.PublicKey, exp ...time.Time) []byte {
	thumb := ThumbprintRSAPublicKey(p)
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(p.N.Bytes())
	expstr := ""
	if 0 != len(exp) {
		expstr = fmt.Sprintf(`"exp":%d,`, exp[0].Unix())
	}
	return []byte(fmt.Sprintf(`{"kid":%q,"use":"sig",%s"e":%q,"kty":"RSA","n":%q}`, thumb, expstr, e, n))
}

// MarshalRSAPublicKeyWithoutKeyID will output the most minimal version of an RSA JWK (no key id, no "use" flag, nada)
func MarshalRSAPublicKeyWithoutKeyID(p *rsa.PublicKey) []byte {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(p.N.Bytes())
	return []byte(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n))
}

// ThumbprintRSAPublicKey will output a RFC-spec SHA256 JWK thumbprint of an EC public key
func ThumbprintRSAPublicKey(p *rsa.PublicKey) string {
	thumbprintable := MarshalRSAPublicKeyWithoutKeyID(p)
	sha := sha256.Sum256([]byte(thumbprintable))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// ParsePrivateKey will try to parse the bytes you give it
// in any of the supported formats: PEM, DER, PKCS8, PKCS1, SEC1, and JWK
func ParsePrivateKey(block []byte) (PrivateKey, error) {
	blocks, err := getPEMBytes(block)
	if nil != err {
		return nil, ErrParsePrivateKey
	}

	// Parse PEM blocks (openssl generates junk metadata blocks for ECs)
	// or the original DER, or the JWK
	for i := range blocks {
		block = blocks[i]
		if key, err := parsePrivateKey(block); nil == err {
			return key, nil
		}
	}

	for i := range blocks {
		block = blocks[i]
		if _, err := parsePublicKey(block); nil == err {
			return nil, ErrUnexpectedPublicKey
		}
	}

	// If we didn't parse a key arleady, we failed
	return nil, ErrParsePrivateKey
}

// ParsePrivateKeyString calls ParsePrivateKey([]byte(key)) for all you lazy folk.
func ParsePrivateKeyString(block string) (PrivateKey, error) {
	return ParsePrivateKey([]byte(block))
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
			err = errors.New("Only RSA and ECDSA (EC) Private Keys are supported")
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

func getPEMBytes(block []byte) ([][]byte, error) {
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

	if len(blocks) > 0 {
		return blocks, nil
	}
	return nil, errors.New("no PEM blocks found")
}

// ParsePublicKey will try to parse the bytes you give it
// in any of the supported formats: PEM, DER, PKIX/SPKI, PKCS1, x509 Certificate, and JWK
func ParsePublicKey(block []byte) (PublicKeyDeprecated, error) {
	blocks, err := getPEMBytes(block)
	if nil != err {
		return nil, ErrParsePublicKey
	}

	// Parse PEM blocks (openssl generates junk metadata blocks for ECs)
	// or the original DER, or the JWK
	for i := range blocks {
		block = blocks[i]
		if key, err := parsePublicKey(block); nil == err {
			return key, nil
		}
	}

	for i := range blocks {
		block = blocks[i]
		if _, err := parsePrivateKey(block); nil == err {
			return nil, ErrUnexpectedPrivateKey
		}
	}

	// If we didn't parse a key arleady, we failed
	return nil, ErrParsePublicKey
}

// ParsePublicKeyString calls ParsePublicKey([]byte(key)) for all you lazy folk.
func ParsePublicKeyString(block string) (PublicKeyDeprecated, error) {
	return ParsePublicKey([]byte(block))
}

func parsePublicKey(der []byte) (PublicKeyDeprecated, error) {
	cert, err := x509.ParseCertificate(der)
	if nil == err {
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			return NewPublicKey(k), nil
		case *ecdsa.PublicKey:
			return NewPublicKey(k), nil
		default:
			return nil, errors.New("Only RSA and ECDSA (EC) Public Keys are supported")
		}
	}

	//fmt.Println("1. ParsePKIXPublicKey")
	xkey, err := x509.ParsePKIXPublicKey(der)
	if nil == err {
		switch k := xkey.(type) {
		case *rsa.PublicKey:
			return NewPublicKey(k), nil
		case *ecdsa.PublicKey:
			return NewPublicKey(k), nil
		default:
			return nil, errors.New("Only RSA and ECDSA (EC) Public Keys are supported")
		}
	}

	//fmt.Println("3. ParsePKCS1PrublicKey")
	rkey, err := x509.ParsePKCS1PublicKey(der)
	if nil == err {
		//fmt.Println("4. ParseJWKPublicKey")
		return NewPublicKey(rkey), nil
	}

	return ParseJWKPublicKey(der)

	/*
		// But did you know?
		// You must return nil explicitly for interfaces
		// https://golang.org/doc/faq#nil_error
		if nil != err {
			return nil, err
		}
	*/
}

// NewJWKPublicKey contstructs a PublicKey from the relevant pieces a map[string]string (generic JSON)
func NewJWKPublicKey(m map[string]string) (PublicKeyDeprecated, error) {
	switch m["kty"] {
	case "RSA":
		return parseRSAPublicKey(m)
	case "EC":
		return parseECPublicKey(m)
	default:
		return nil, ErrInvalidKeyType
	}
}

// ParseJWKPublicKey parses a JSON-encoded JWK and returns a PublicKey, or a (hopefully) helpful error message
func ParseJWKPublicKey(b []byte) (PublicKeyDeprecated, error) {
	// RSA and EC have "d" as a private part
	if bytes.Contains(b, []byte(`"d"`)) {
		return nil, ErrUnexpectedPrivateKey
	}
	return newJWKPublicKey(b)
}

// ParseJWKPublicKeyString calls ParseJWKPublicKey([]byte(key)) for all you lazy folk.
func ParseJWKPublicKeyString(s string) (PublicKeyDeprecated, error) {
	if strings.Contains(s, `"d"`) {
		return nil, ErrUnexpectedPrivateKey
	}
	return newJWKPublicKey(s)
}

// DecodeJWKPublicKey stream-decodes a JSON-encoded JWK and returns a PublicKey, or a (hopefully) helpful error message
func DecodeJWKPublicKey(r io.Reader) (PublicKeyDeprecated, error) {
	m := make(map[string]string)
	if err := json.NewDecoder(r).Decode(&m); nil != err {
		return nil, err
	}
	if d := m["d"]; "" != d {
		return nil, ErrUnexpectedPrivateKey
	}
	return newJWKPublicKey(m)
}

// the underpinnings of the parser as used by the typesafe wrappers
func newJWKPublicKey(data interface{}) (PublicKeyDeprecated, error) {
	var m map[string]string

	switch d := data.(type) {
	case map[string]string:
		m = d
	case string:
		if err := json.Unmarshal([]byte(d), &m); nil != err {
			return nil, err
		}
	case []byte:
		if err := json.Unmarshal(d, &m); nil != err {
			return nil, err
		}
	default:
		panic("Developer Error: unsupported interface type")
	}

	return NewJWKPublicKey(m)
}

// ParseJWKPrivateKey parses a JSON-encoded JWK and returns a PrivateKey, or a (hopefully) helpful error message
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
		return nil, ErrInvalidKeyType
	}
}

func parseRSAPublicKey(m map[string]string) (*RSAPublicKey, error) {
	// TODO grab expiry?
	kid, _ := m["kid"]
	n, _ := base64.RawURLEncoding.DecodeString(m["n"])
	e, _ := base64.RawURLEncoding.DecodeString(m["e"])
	if 0 == len(n) || 0 == len(e) {
		return nil, ErrParseJWK
	}
	ni := &big.Int{}
	ni.SetBytes(n)
	ei := &big.Int{}
	ei.SetBytes(e)

	pub := &rsa.PublicKey{
		N: ni,
		E: int(ei.Int64()),
	}

	return &RSAPublicKey{
		PublicKey: pub,
		KID:       kid,
	}, nil
}

func parseRSAPrivateKey(m map[string]string) (key *rsa.PrivateKey, err error) {
	pub, err := parseRSAPublicKey(m)
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
		return nil, ErrParseJWK
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
		PublicKey: *pub.PublicKey,
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

func parseECPublicKey(m map[string]string) (*ECPublicKey, error) {
	// TODO grab expiry?
	kid, _ := m["kid"]
	x, _ := base64.RawURLEncoding.DecodeString(m["x"])
	y, _ := base64.RawURLEncoding.DecodeString(m["y"])
	if 0 == len(x) || 0 == len(y) || 0 == len(m["crv"]) {
		return nil, ErrParseJWK
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
		return nil, ErrInvalidCurve
	}

	pub := &ecdsa.PublicKey{
		Curve: crv,
		X:     xi,
		Y:     yi,
	}

	return &ECPublicKey{
		PublicKey: pub,
		KID:       kid,
	}, nil
}

func parseECPrivateKey(m map[string]string) (*ecdsa.PrivateKey, error) {
	pub, err := parseECPublicKey(m)
	if nil != err {
		return nil, err
	}

	d, _ := base64.RawURLEncoding.DecodeString(m["d"])
	if 0 == len(d) {
		return nil, ErrParseJWK
	}
	di := &big.Int{}
	di.SetBytes(d)

	return &ecdsa.PrivateKey{
		PublicKey: *pub.PublicKey,
		D:         di,
	}, nil
}
