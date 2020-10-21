package keypairs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand" // to be used for good, not evil
	"time"
)

// Object is a type alias representing generic JSON data
type Object = map[string]interface{}

// SignClaims adds `typ`, `kid` (or `jwk`), and `alg` in the header and expects claims for `jti`, `exp`, `iss`, and `iat`
func SignClaims(privkey PrivateKey, header Object, claims Object) (*JWS, error) {
	var randsrc io.Reader = randReader
	seed, _ := header["_seed"].(int64)
	if 0 != seed {
		randsrc = mathrand.New(mathrand.NewSource(seed))
		//delete(header, "_seed")
	}

	protected, header, err := headerToProtected(privkey.Public().(PublicKeyTransitional), header)
	if nil != err {
		return nil, err
	}
	protected64 := base64.RawURLEncoding.EncodeToString(protected)

	payload, err := claimsToPayload(claims)
	if nil != err {
		return nil, err
	}
	payload64 := base64.RawURLEncoding.EncodeToString(payload)

	signable := fmt.Sprintf(`%s.%s`, protected64, payload64)
	hash := sha256.Sum256([]byte(signable))

	sig := Sign(privkey, hash[:], randsrc)
	sig64 := base64.RawURLEncoding.EncodeToString(sig)
	//log.Printf("\n(Sign)\nSignable: %s", signable)
	//log.Printf("Hash: %s", hash)
	//log.Printf("Sig: %s", sig64)

	return &JWS{
		Header:    header,
		Claims:    claims,
		Protected: protected64,
		Payload:   payload64,
		Signature: sig64,
	}, nil
}

func headerToProtected(pub PublicKeyTransitional, header Object) ([]byte, Object, error) {
	if nil == header {
		header = Object{}
	}

	// Only supporting 2048-bit and P256 keys right now
	// because that's all that's practical and well-supported.
	// No security theatre here.
	alg := "ES256"
	switch pub.(type) {
	case *rsa.PublicKey:
		alg = "RS256"
	}

	if selfSign, _ := header["_jwk"].(bool); selfSign {
		delete(header, "_jwk")
		any := Object{}
		_ = json.Unmarshal(MarshalJWKPublicKey(pub), &any)
		header["jwk"] = any
	}

	// TODO what are the acceptable values? JWT. JWS? others?
	header["typ"] = "JWT"
	if _, ok := header["jwk"]; !ok {
		thumbprint := ThumbprintPublicKey(NewPublicKey(pub))
		kid, _ := header["kid"].(string)
		if "" != kid && thumbprint != kid {
			return nil, nil, errors.New("'kid' should be the key's thumbprint")
		}
		header["kid"] = thumbprint
	}
	header["alg"] = alg

	protected, err := json.Marshal(header)
	if nil != err {
		return nil, nil, err
	}
	return protected, header, nil
}

func claimsToPayload(claims Object) ([]byte, error) {
	if nil == claims {
		claims = Object{}
	}

	var dur time.Duration
	jti, _ := claims["jti"].(string)
	insecure, _ := claims["insecure"].(bool)

	switch exp := claims["exp"].(type) {
	case time.Duration:
		// TODO: MUST this go first?
		// int64(time.Duration) vs time.Duration(int64)
		dur = exp
	case string:
		var err error
		dur, err = time.ParseDuration(exp)
		// TODO s, err := time.ParseDuration(dur)
		if nil != err {
			return nil, err
		}
	case int:
		dur = time.Second * time.Duration(exp)
	case int64:
		dur = time.Second * time.Duration(exp)
	case float64:
		dur = time.Second * time.Duration(exp)
	default:
		dur = 0
	}

	if "" == jti && 0 == dur && !insecure {
		return nil, errors.New("token must have jti or exp as to be expirable / cancellable")
	}
	claims["exp"] = time.Now().Add(dur).Unix()

	return json.Marshal(claims)
}

// Sign signs both RSA and ECDSA. Use `nil` or `crypto/rand.Reader` except for debugging.
func Sign(privkey PrivateKey, hash []byte, rand io.Reader) []byte {
	if nil == rand {
		rand = randReader
	}
	var sig []byte

	if len(hash) != 32 {
		panic("only 256-bit hashes for 2048-bit and 256-bit keys are supported")
	}

	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		sig, _ = rsa.SignPKCS1v15(rand, k, crypto.SHA256, hash)
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand, k, hash[:])
		rb := r.Bytes()
		for len(rb) < 32 {
			rb = append([]byte{0}, rb...)
		}
		sb := s.Bytes()
		for len(rb) < 32 {
			sb = append([]byte{0}, sb...)
		}
		sig = append(rb, sb...)
	}
	return sig
}
