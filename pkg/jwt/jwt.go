package jwt

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func New() {
	tokenString, err := createSignedTokenString()
	if err != nil {
		log.Fatal(err)
	}

	tokenFile := "_output/token"
	f, err := os.Create(tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.WriteString(tokenString)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Token written to ", tokenFile)

	/*token, err := parseTokenFromSignedTokenString(tokenString)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed token valid = %v, raw token:\n%v\n", token.Valid, token.Raw)*/
}

func createSignedTokenString() (string, error) {
	privateKey, err := ioutil.ReadFile("_output/sa-signer")
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
	token.Header["kid"] = "Rwcrfsg-0jyoVhNHpud261N1JzdPC0f1XpOsj6kMPBI"
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("error signing token: %v\n", err)
	}

	return tokenString, nil
}

/*func parseTokenFromSignedTokenString(tokenString string) (*jwt.Token, error) {
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
}*/
