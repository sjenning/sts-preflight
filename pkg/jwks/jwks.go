package jwks

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	jose "gopkg.in/square/go-jose.v2"
)

func New() {
	pubKeyFile := "_output/sa-signer.pub"
	keysFile := "_output/keys.json"

	log.Print("Reading public key")
	content, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	block, _ := pem.Decode(content)
	if block == nil {
		log.Fatal("Error decoding PEM file")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("Error parsing key content")
	}
	switch pubKey.(type) {
	case *rsa.PublicKey:
	default:
		log.Fatal("Public key was not RSA")
	}

	var alg jose.SignatureAlgorithm
	switch pubKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		log.Fatal("Public key type must be *rsa.PublicKey")
	}

	kid, err := keyIDFromPublicKey(pubKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})

	keysJSON, err := json.MarshalIndent(KeyResponse{Keys: keys}, "", "    ")
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Print("Writing JWKS to ", keysFile)
	f, err := os.Create(keysFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer f.Close()
	f.Write(keysJSON)
}

// copied from kubernetes/kubernetes#78502
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

type KeyResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}
