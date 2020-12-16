package keys

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/sjenning/sts-preflight/pkg/cmd/create"
	"github.com/sjenning/sts-preflight/pkg/jwks"
	"github.com/sjenning/sts-preflight/pkg/rsa"
)

const (
	privateKey           = "sa-signer"
	publicKey            = "sa-signer.pub"
	nextSigningKeySecret = "next-bound-service-account-signing-key"
)

func GenerateKeys(config Config) {
	rsa.New(config.TargetDir)

	jwks.New(&create.State{}, config.TargetDir)

	if config.ExistingKeysJSONFile != "" {
		jwks.MergeKeys(config.ExistingKeysJSONFile, config.TargetDir)
	}
}

func GenerateSecret(config Config) {
	secretTemplate := `apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: %s
  namespace: openshift-kube-apiserver-operator
data:
  service-account.key: %s
  service-account.pub: %s`

	privateKeyPath := filepath.Join(config.TargetDir, privateKey)
	publicKeyPath := filepath.Join(config.TargetDir, publicKey)

	privateKeyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read in private key: %s", err)
	}

	publicKeyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to read in public key: %s", err)
	}

	privateBase64 := base64.StdEncoding.EncodeToString(privateKeyData)
	publicBase64 := base64.StdEncoding.EncodeToString(publicKeyData)

	secretData := fmt.Sprintf(secretTemplate, nextSigningKeySecret, privateBase64, publicBase64)

	nextSecretFile := filepath.Join(config.TargetDir, nextSigningKeySecret)
	if err := ioutil.WriteFile(nextSecretFile, []byte(secretData), 0600); err != nil {
		log.Fatalf("Failed to save Secret with next signing key data: %s", err)
	}
}
