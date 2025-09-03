package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
)

// NOTE: Full spec: https://datatracker.ietf.org/doc/html/rfc7517#section-4
// REF: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm used
	Kty string `json:"kty"` // Key type (type of crypto algorithm used)
	E   string `json:"e"`   // Exponent of the RSA public key
	N   string `json:"n"`   // Modulus of the RSA public key
	Use string `json:"use"` // Intended use of this public key, "sig" for signature | "enc" for encryption
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Fetches JWKS from the well-known endpoint
func (j *JWKS) fetch(jwksURL string) error {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status code %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(j); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return nil
}

type KeyID = string
type PublicKeys = map[KeyID]*rsa.PublicKey

// Creates public keys from JWKS
func createPublicKeys(jwks *JWKS) (PublicKeys, error) {
	publicKeys := make(PublicKeys)

	for _, jwk := range jwks.Keys {
		// Only process RSA keys intended for signature verification
		if jwk.Kty == "RSA" && jwk.Use == "sig" {
			publicKey, err := jwkToRSAPublicKey(jwk)
			if err != nil {
				return nil, fmt.Errorf("failed to convert JWK to RSA public key for kid %s: %w", jwk.Kid, err)
			}
			publicKeys[jwk.Kid] = publicKey
		}
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no valid RSA signature keys found in JWKS")
	}

	return publicKeys, nil
}

// Converts JWK to RSA public key
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	mod, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	exp, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(mod)
	e := new(big.Int).SetBytes(exp)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

type JWTHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type JWTPayload struct {
	Exp   int64  `json:"exp"`
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
}

type JWT struct {
	Header    JWTHeader
	Payload   JWTPayload
	Signature []byte

	HeaderStr    string
	PayloadStr   string
	SignatureStr string
}

func newJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
	}

	headerStr := parts[0]
	payloadStr := parts[1]
	signatureStr := parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return &JWT{
		Header:       header,
		Payload:      payload,
		Signature:    signature,
		HeaderStr:    headerStr,
		PayloadStr:   payloadStr,
		SignatureStr: signatureStr,
	}, nil
}

func (jwt JWT) verifySignature(pk PublicKeys) (bool, error) {
	if jwt.Header.Alg != "RS256" {
		return false, fmt.Errorf("unsupported algorithm: %s", jwt.Header.Alg)
	}

	publicKey := pk[jwt.Header.Kid]
	if publicKey == nil {
		return false, fmt.Errorf("public key not found for kid: %s", jwt.Header.Kid)
	}

	signingInput := jwt.HeaderStr + "." + jwt.PayloadStr

	// Hash the signing input with SHA-256
	hash := sha256.Sum256([]byte(signingInput))

	// Verify the signature using RSA-PSS or PKCS1v15
	// JWT typically uses PKCS1v15 for RS256
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], jwt.Signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	return true, nil
}

func main() {
	jwksURL := os.Getenv("COGNITO_JWKS_URL")
	if jwksURL == "" {
		log.Fatalf("Environment variable COGNITO_JWKS_URL is not set")
	}

	tokenStr := os.Getenv("ACCESS_TOKEN")
	if tokenStr == "" {
		log.Fatalf("Environment variable ACCESS_TOKEN is not set")
	}
	jwt, err := newJWT(tokenStr)
	if err != nil {
		log.Fatalf("Failed to create JWT: %v", err)
	}

	var jwks JWKS
	if err := jwks.fetch(jwksURL); err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}

	publicKeys, err := createPublicKeys(&jwks)
	if err != nil {
		log.Fatalf("Failed to create public keys: %v", err)
	}

	fmt.Printf("Successfully reconstructed %d public keys from JWKS:\n", len(publicKeys))
	for kid, pubKey := range publicKeys {
		fmt.Printf("- Key ID: %s, Modulus size: %d bits\n", kid, pubKey.N.BitLen())
	}

	isValidSignature, err := jwt.verifySignature(publicKeys)
	if err != nil {
		log.Fatalf("Failed to verify token: %v", err)
	}

	fmt.Println("\nJWT:", tokenStr)
	fmt.Println("\nIs token signature valid?", isValidSignature)
}
