package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func New() {
	privateKeyFile := "_output/sa-signer"
	publicKeyFile := "_output/sa-signer.pub"
	bitSize := 4096

	_, err := os.Stat(privateKeyFile)
	if err == nil {
		log.Print("Using existing RSA keypair")
		return
	}

	log.Print("Generating RSA keypair")
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Print("Writing private key to ", privateKeyFile)
	f, err := os.Create(privateKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = pem.Encode(f, &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})
	f.Close()
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Print("Writing public key to ", publicKeyFile)
	f, err = os.Create(publicKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = pem.Encode(f, &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	})
	f.Close()
	if err != nil {
		log.Fatal(err.Error())
	}
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}
