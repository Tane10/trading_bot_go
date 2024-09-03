package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/lpernett/godotenv"
	log "github.com/sirupsen/logrus"
)

func loadEnvs() (string, []byte) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error to load .env file: %v", err)
	}

	apiKeyName := os.Getenv("API_KEY_NAME")

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
	}

	filePath := filepath.Join(cwd, "secret.pem")

	pemData, err := os.ReadFile(filePath)

	if err != nil {
		log.Fatalf("Error reading PEM file: %v", err)
	}

	return apiKeyName, pemData
}

var maxInt = big.NewInt(math.MaxInt64)

type nonceSource struct{}

func (n nonceSource) Nonce() (string, error) {
	r, err := rand.Int(rand.Reader, maxInt)

	if err != nil {
		return "", err
	}

	return r.String(), nil
}

type APIKeyClaims struct {
	*jwt.Claims
	URI string `json:"uri"`
}

func buildJWT(uri string) (string, error) {
	apiKeyName, pemData := loadEnvs()

	block, rest := pem.Decode(pemData)

	if block == nil {
		fmt.Println(block)
		fmt.Println(string(rest))
		return "", fmt.Errorf("jwt: Could not decode private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("jwt: %w", err)
	}

	signature, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{NonceSource: nonceSource{}}).WithType("JWT").WithHeader("kid", apiKeyName),
	)

	if err != nil {
		return "", fmt.Errorf("jwt: %w", err)
	}

	cl := &APIKeyClaims{
		Claims: &jwt.Claims{
			Subject:   apiKeyName,
			Issuer:    "cdp",
			NotBefore: jwt.NewNumericDate(time.Now()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
		},
		URI: uri,
	}

	jwtString, err := jwt.Signed(signature).Claims(cl).Serialize()

	if err != nil {
		return "", fmt.Errorf("jwt: %v", err)
	}

	return jwtString, nil

}

func main() {
	requestMethod := "GET"
	requestHost := "api.coinbase.com"
	requestPath := "/v2/accounts"

	uri := fmt.Sprintf("%s %s%s", requestMethod, requestHost, requestPath)

	jwt, err := buildJWT(uri)

	if err != nil {
		log.Errorf("error building jwt: %v", err)
	}

	fmt.Println(fmt.Sprintf("export JWT= %w", jwt))
}
