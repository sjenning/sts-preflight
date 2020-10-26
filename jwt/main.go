package main

import (
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	tokenString, err := createSignedTokenString()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signed token string:\n%v\n", tokenString)

	token, err := parseTokenFromSignedTokenString(tokenString)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed token valid = %v, raw token:\n%v\n", token.Valid, token.Raw)
}

func createSignedTokenString() (string, error) {
	privateKey, err := ioutil.ReadFile("../sa-signer")
	if err != nil {
		return "", fmt.Errorf("error reading private key file: %v\n", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", fmt.Errorf("error parsing RSA private key: %v\n", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "openshift-installer",
		"aud": "sts.amazonaws.com",
		"iss": "https://s3-us-west-1.amazonaws.com/sjenning-oidc-provider",
		"exp": time.Now().Unix() + 3600,
		"iat": time.Now().Unix(),
	})
	token.Header["kid"] = "_lopSuXylhCTAFUOVwsdCAbPANX5NK3MwfqofKuhSXg"
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("error signing token: %v\n", err)
	}

	return tokenString, nil
}

func parseTokenFromSignedTokenString(tokenString string) (*jwt.Token, error) {
	publicKey, err := ioutil.ReadFile("../sa-signer-pkcs8.pub")
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v\n", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA public key: %v\n", err)
	}

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	return parsedToken, nil
}
