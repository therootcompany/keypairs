package keypairs

import (
	"fmt"
)

// JWK abstracts EC and RSA keys
type JWK interface {
	marshalJWK() ([]byte, error)
}

// ECJWK is the EC variant
type ECJWK struct {
	KeyID string   `json:"kid,omitempty"`
	Curve string   `json:"crv"`
	X     string   `json:"x"`
	Y     string   `json:"y"`
	Use   []string `json:"use,omitempty"`
	Seed  string   `json:"_seed,omitempty"`
}

func (k *ECJWK) marshalJWK() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Curve, k.X, k.Y)), nil
}

// RSAJWK is the RSA variant
type RSAJWK struct {
	KeyID string   `json:"kid,omitempty"`
	Exp   string   `json:"e"`
	N     string   `json:"n"`
	Use   []string `json:"use,omitempty"`
	Seed  string   `json:"_seed,omitempty"`
}

func (k *RSAJWK) marshalJWK() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.Exp, k.N)), nil
}

/*
// ToPublicJWK exposes only the public parts
func ToPublicJWK(pubkey PublicKey) JWK {
	switch k := pubkey.Key().(type) {
	case *ecdsa.PublicKey:
		return ECToPublicJWK(k)
	case *rsa.PublicKey:
		return RSAToPublicJWK(k)
	default:
		panic(errors.New("impossible key type"))
		//return nil
	}
}

// ECToPublicJWK will output the most minimal version of an EC JWK (no key id, no "use" flag, nada)
func ECToPublicJWK(k *ecdsa.PublicKey) *ECJWK {
	return &ECJWK{
		Curve: k.Curve.Params().Name,
		X:     base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:     base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	}
}

// RSAToPublicJWK will output the most minimal version of an RSA JWK (no key id, no "use" flag, nada)
func RSAToPublicJWK(p *rsa.PublicKey) *RSAJWK {
	return &RSAJWK{
		Exp: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes()),
		N:   base64.RawURLEncoding.EncodeToString(p.N.Bytes()),
	}
}
*/
