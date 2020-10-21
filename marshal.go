package keypairs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
)

// MarshalPEMPublicKey outputs the given public key as JWK
func MarshalPEMPublicKey(pubkey PublicKeyTransitional) ([]byte, error) {
	block, err := marshalDERPublicKey(pubkey)
	if nil != err {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalDERPublicKey outputs the given public key as JWK
func MarshalDERPublicKey(pubkey PublicKeyTransitional) ([]byte, error) {
	block, err := marshalDERPublicKey(pubkey)
	if nil != err {
		return nil, err
	}
	return block.Bytes, nil
}

// marshalDERPublicKey outputs the given public key as JWK
func marshalDERPublicKey(pubkey PublicKeyTransitional) (*pem.Block, error) {

	var der []byte
	var typ string
	var err error
	switch k := pubkey.(type) {
	case *rsa.PublicKey:
		der = x509.MarshalPKCS1PublicKey(k)
		typ = "RSA PUBLIC KEY"
	case *ecdsa.PublicKey:
		typ = "PUBLIC KEY"
		der, err = x509.MarshalPKIXPublicKey(k)
		if nil != err {
			return nil, err
		}
	default:
		panic("Developer Error: impossible key type")
	}

	return &pem.Block{
		Bytes: der,
		Type:  typ,
	}, nil
}

// MarshalJWKPrivateKey outputs the given private key as JWK
func MarshalJWKPrivateKey(privkey PrivateKey) []byte {
	// thumbprint keys are alphabetically sorted and only include the necessary public parts
	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		return MarshalRSAPrivateKey(k)
	case *ecdsa.PrivateKey:
		return MarshalECPrivateKey(k)
	default:
		// this is unreachable because we know the types that we pass in
		log.Printf("keytype: %t, %+v\n", privkey, privkey)
		panic(ErrInvalidPublicKey)
		//return nil
	}
}

// MarshalDERPrivateKey outputs the given private key as ASN.1 DER
func MarshalDERPrivateKey(privkey PrivateKey) ([]byte, error) {
	// thumbprint keys are alphabetically sorted and only include the necessary public parts
	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	default:
		// this is unreachable because we know the types that we pass in
		log.Printf("keytype: %t, %+v\n", privkey, privkey)
		panic(ErrInvalidPublicKey)
		//return nil, nil
	}
}

func marshalDERPrivateKey(privkey PrivateKey) (*pem.Block, error) {
	var typ string
	var bytes []byte
	var err error

	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		if 0 == mathrand.Intn(2) {
			typ = "PRIVATE KEY"
			bytes, err = x509.MarshalPKCS8PrivateKey(k)
			if nil != err {
				return nil, err
			}
		} else {
			typ = "RSA PRIVATE KEY"
			bytes = x509.MarshalPKCS1PrivateKey(k)
		}
		return &pem.Block{
			Type:  typ,
			Bytes: bytes,
		}, nil
	case *ecdsa.PrivateKey:
		if 0 == mathrand.Intn(2) {
			typ = "PRIVATE KEY"
			bytes, err = x509.MarshalPKCS8PrivateKey(k)
		} else {
			typ = "EC PRIVATE KEY"
			bytes, err = x509.MarshalECPrivateKey(k)
		}
		if nil != err {
			return nil, err
		}
		return &pem.Block{
			Type:  typ,
			Bytes: bytes,
		}, nil
	default:
		// this is unreachable because we know the types that we pass in
		log.Printf("keytype: %t, %+v\n", privkey, privkey)
		panic(ErrInvalidPublicKey)
		//return nil, nil
	}
}

// MarshalPEMPrivateKey outputs the given private key as ASN.1 PEM
func MarshalPEMPrivateKey(privkey PrivateKey) ([]byte, error) {
	block, err := marshalDERPrivateKey(privkey)
	if nil != err {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalECPrivateKey will output the given private key as JWK
func MarshalECPrivateKey(k *ecdsa.PrivateKey) []byte {
	crv := k.Curve.Params().Name
	d := base64.RawURLEncoding.EncodeToString(k.D.Bytes())
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	return []byte(fmt.Sprintf(
		`{"crv":%q,"d":%q,"kty":"EC","x":%q,"y":%q}`,
		crv, d, x, y,
	))
}

// MarshalRSAPrivateKey will output the given private key as JWK
func MarshalRSAPrivateKey(pk *rsa.PrivateKey) []byte {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pk.N.Bytes())
	d := base64.RawURLEncoding.EncodeToString(pk.D.Bytes())
	p := base64.RawURLEncoding.EncodeToString(pk.Primes[0].Bytes())
	q := base64.RawURLEncoding.EncodeToString(pk.Primes[1].Bytes())
	dp := base64.RawURLEncoding.EncodeToString(pk.Precomputed.Dp.Bytes())
	dq := base64.RawURLEncoding.EncodeToString(pk.Precomputed.Dq.Bytes())
	qi := base64.RawURLEncoding.EncodeToString(pk.Precomputed.Qinv.Bytes())
	return []byte(fmt.Sprintf(
		`{"d":%q,"dp":%q,"dq":%q,"e":%q,"kty":"RSA","n":%q,"p":%q,"q":%q,"qi":%q}`,
		d, dp, dq, e, n, p, q, qi,
	))
}
