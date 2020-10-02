package keypairs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// JWS is a parsed JWT, representation as signable/verifiable and human-readable parts
type JWS struct {
	Header    Object `json:"header"`    // JSON
	Claims    Object `json:"claims"`    // JSON
	Protected string `json:"protected"` // base64
	Payload   string `json:"payload"`   // base64
	Signature string `json:"signature"` // base64
}

// JWSToJWT joins JWS parts into a JWT as {ProtectedHeader}.{SerializedPayload}.{Signature}.
func JWSToJWT(jwt *JWS) string {
	return fmt.Sprintf(
		"%s.%s.%s",
		jwt.Protected,
		jwt.Payload,
		jwt.Signature,
	)
}

// JWTToJWS splits the JWT into its JWS segments
func JWTToJWS(jwt string) (jws *JWS) {
	jwt = strings.TrimSpace(jwt)
	parts := strings.Split(jwt, ".")
	if 3 != len(parts) {
		return nil
	}
	return &JWS{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
	}
}

// DecodeComponents decodes JWS Header and Claims
func (jws *JWS) DecodeComponents() error {
	protected, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if nil != err {
		return errors.New("invalid JWS header base64Url encoding")
	}
	if err := json.Unmarshal([]byte(protected), &jws.Header); nil != err {
		return errors.New("invalid JWS header")
	}

	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if nil != err {
		return errors.New("invalid JWS payload base64Url encoding")
	}
	if err := json.Unmarshal([]byte(payload), &jws.Claims); nil != err {
		return errors.New("invalid JWS claims")
	}

	return nil
}
