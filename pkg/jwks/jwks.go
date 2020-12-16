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
	"path/filepath"

	"github.com/sjenning/sts-preflight/pkg/cmd/create"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	keysJSONFile = "keys.json"
)

func New(state *create.State, targetDir string) {
	pubKeyFile := filepath.Join(targetDir, "sa-signer.pub")
	keysFile := filepath.Join(targetDir, keysJSONFile)

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

	state.Kid = kid

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
	_, err = f.Write(keysJSON)
	f.Close()
	if err != nil {
		log.Fatal(err.Error())
	}
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

func MergeKeys(existingKeysFile, mergeWithKeysInTargetDir string) {
	existingKeysData, err := ioutil.ReadFile(existingKeysFile)
	if err != nil {
		log.Fatalf("Failed to read in existing keys file: %s", err)
	}

	existingKeys := KeyResponse{}
	if err := json.Unmarshal(existingKeysData, &existingKeys); err != nil {
		log.Fatalf("Failed to unmarshal: %s", err)
	}

	mergeWithUpdatedKeysFile := filepath.Join(mergeWithKeysInTargetDir, keysJSONFile)

	log.Printf("Merging previous keys.json into %s", mergeWithUpdatedKeysFile)

	updateKeysData, err := ioutil.ReadFile(mergeWithUpdatedKeysFile)
	if err != nil {
		log.Fatalf("Failed to read in new keys file: %s", err)
	}

	updateKeys := KeyResponse{}
	if err := json.Unmarshal(updateKeysData, &updateKeys); err != nil {
		log.Fatalf("Failed to unmarshal: %s", err)
	}

	for _, key := range updateKeys.Keys {
		existingKeys.Keys = append(existingKeys.Keys, key)
	}

	newKeysJSON, err := json.MarshalIndent(existingKeys, "", "    ")
	if err != nil {
		log.Fatalf("Failed to marshal keys JSON: %s", err)
	}

	if err := ioutil.WriteFile(mergeWithUpdatedKeysFile, newKeysJSON, 0644); err != nil {
		log.Fatalf("Failed to save merged keys file: %s", err)
	}
}
