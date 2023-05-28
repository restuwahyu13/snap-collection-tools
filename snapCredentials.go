package main

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
)

const (
	PRIVPKCS1 = "RSA PRIVATE KEY"
	PRIVPKCS8 = "PRIVATE KEY"

	PUBPKCS1 = "RSA PUBLIC KEY"
	PUBPKCS8 = "PUBLIC KEY"
)

func PrivateKey(value string) string {
	var privateKey string

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return ""
	}

	pemDecoded, _ := pem.Decode([]byte(decoded))
	if pemDecoded == nil {
		return ""
	}

	if pemDecoded.Type == PRIVPKCS1 {
		privateKey = strings.TrimSpace(string(pem.EncodeToMemory(pemDecoded)))
	} else if pemDecoded.Type == PRIVPKCS8 {
		privateKey = strings.TrimSpace(string(pem.EncodeToMemory(pemDecoded)))
	} else {
		return ""
	}

	return privateKey
}

func PublicKey(value string) string {
	var publicKey string

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return ""
	}

	pemDecoded, _ := pem.Decode([]byte(decoded))
	if pemDecoded == nil {
		return ""
	}

	if pemDecoded.Type == PUBPKCS1 {
		publicKey = strings.TrimSpace(string(pem.EncodeToMemory(pemDecoded)))
	} else if pemDecoded.Type == PUBPKCS8 {
		publicKey = strings.TrimSpace(string(pem.EncodeToMemory(pemDecoded)))
	} else {
		return ""
	}

	return publicKey
}
