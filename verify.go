package keypairs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"
)

// VerifyClaims will check the signature of a parsed JWT
func VerifyClaims(pubkey PublicKeyTransitional, jws *JWS) (errs []error) {
	kid, _ := jws.Header["kid"].(string)
	jwkmap, hasJWK := jws.Header["jwk"].(Object)
	//var jwk JWK = nil

	seed, _ := jws.Header["_seed"].(int64)
	seedf64, _ := jws.Header["_seed"].(float64)
	kty, _ := jws.Header["_kty"].(string)
	if 0 == seed {
		seed = int64(seedf64)
	}

	var pub PublicKeyTransitional = nil
	if hasJWK {
		pub, errs = selfsignCheck(jwkmap, errs)
	} else {
		opts := &keyOptions{mockSeed: seed, KeyType: kty}
		pub, errs = pubkeyCheck(pubkey, kid, opts, errs)
	}

	jti, _ := jws.Claims["jti"].(string)
	expf64, _ := jws.Claims["exp"].(float64)
	exp := int64(expf64)
	if 0 == exp {
		if "" == jti {
			err := errors.New("one of 'jti' or 'exp' must exist for token expiry")
			errs = append(errs, err)
		}
	} else {
		if time.Now().Unix() > exp {
			err := fmt.Errorf("token expired at %d (%s)", exp, time.Unix(exp, 0))
			errs = append(errs, err)
		}
	}

	signable := fmt.Sprintf("%s.%s", jws.Protected, jws.Payload)
	hash := sha256.Sum256([]byte(signable))
	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if nil != err {
		err := fmt.Errorf("could not decode signature: %w", err)
		errs = append(errs, err)
		return errs
	}

	//log.Printf("\n(Verify)\nSignable: %s", signable)
	//log.Printf("Hash: %s", hash)
	//log.Printf("Sig: %s", jws.Signature)
	if nil == pub {
		err := fmt.Errorf("token signature could not be verified")
		errs = append(errs, err)
	} else if !Verify(pub, hash[:], sig) {
		err := fmt.Errorf("token signature is not valid")
		errs = append(errs, err)
	}
	return errs
}

func selfsignCheck(jwkmap Object, errs []error) (PublicKeyTransitional, []error) {
	var pub PublicKeyDeprecated = nil
	log.Println("Security TODO: did not check jws.Claims[\"sub\"] against 'jwk'")
	log.Println("Security TODO: did not check jws.Claims[\"iss\"]")
	kty := jwkmap["kty"]
	var err error
	if "RSA" == kty {
		e, _ := jwkmap["e"].(string)
		n, _ := jwkmap["n"].(string)
		k, _ := (&RSAJWK{
			Exp: e,
			N:   n,
		}).marshalJWK()
		pub, err = ParseJWKPublicKey(k)
		if nil != err {
			return nil, append(errs, err)
		}
	} else {
		crv, _ := jwkmap["crv"].(string)
		x, _ := jwkmap["x"].(string)
		y, _ := jwkmap["y"].(string)
		k, _ := (&ECJWK{
			Curve: crv,
			X:     x,
			Y:     y,
		}).marshalJWK()
		pub, err = ParseJWKPublicKey(k)
		if nil != err {
			return nil, append(errs, err)
		}
	}

	return pub.Key().(PublicKeyTransitional), errs
}

func pubkeyCheck(pubkey PublicKeyTransitional, kid string, opts *keyOptions, errs []error) (PublicKeyTransitional, []error) {
	var pub PublicKeyTransitional = nil

	if "" == kid {
		err := errors.New("token should have 'kid' or 'jwk' in header to identify the public key")
		errs = append(errs, err)
	}

	if nil == pubkey {
		if allowMocking {
			if 0 == opts.mockSeed {
				err := errors.New("the debug API requires '_seed' to accompany 'kid'")
				errs = append(errs, err)
			}
			if "" == opts.KeyType {
				err := errors.New("the debug API requires '_kty' to accompany '_seed'")
				errs = append(errs, err)
			}

			if 0 == opts.mockSeed || "" == opts.KeyType {
				return nil, errs
			}
			privkey := newPrivateKey(opts)
			pub = privkey.Public().(PublicKeyTransitional)
			return pub, errs
		}
		err := errors.New("no matching public key")
		errs = append(errs, err)
	} else {
		pub = pubkey
	}

	if nil != pub && "" != kid {
		if 1 != subtle.ConstantTimeCompare([]byte(kid), []byte(Thumbprint(pub))) {
			err := errors.New("'kid' does not match the public key thumbprint")
			errs = append(errs, err)
		}
	}
	return pub, errs
}

// Verify will check the signature of a hash
func Verify(pubkey PublicKeyTransitional, hash []byte, sig []byte) bool {

	switch pub := pubkey.(type) {
	case *rsa.PublicKey:
		//log.Printf("RSA VERIFY")
		// TODO Size(key) to detect key size ?
		//alg := "SHA256"
		// TODO: this hasn't been tested yet
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, sig); nil != err {
			return false
		}
		return true
	case *ecdsa.PublicKey:
		r := &big.Int{}
		r.SetBytes(sig[0:32])
		s := &big.Int{}
		s.SetBytes(sig[32:])
		return ecdsa.Verify(pub, hash, r, s)
	default:
		panic("impossible condition: non-rsa/non-ecdsa key")
		//return false
	}
}
