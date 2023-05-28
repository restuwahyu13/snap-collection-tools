package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"

	"reflect"
	"strings"
)

type VerifySignature struct {
	PublicKey    string      `json:"publicKey,omitempty"`
	PrivateKey   string      `json:"privateKey,omitempty"`
	Signature    string      `json:"signature,omitempty"`
	ClientId     string      `json:"clientId,omitempty"`
	Timestamp    string      `json:"timestamp,omitempty"`
	ClientSecret string      `json:"clientSecret,omitempty"`
	AccessToken  string      `json:"accessToken,omitempty"`
	Body         interface{} `json:"body,omitempty"`
}

func SnapVerifyTokenB2B(req *VerifySignature) error {
	var publicKey *rsa.PublicKey

	headers := AsymmetricSignatureSnap{}
	headers.TimeStamp = req.Timestamp
	headers.ClientKey = req.ClientId
	headers.PublicKey = req.PublicKey

	cipherBody := []byte(headers.ClientKey + "|" + headers.TimeStamp)
	cipherBodyHash256 := sha256.New()
	cipherBodyHash256.Write(cipherBody)
	cipherBodyHash := cipherBodyHash256.Sum(nil)

	pemDecoded, _ := pem.Decode([]byte(headers.PublicKey))
	if pemDecoded == nil {
		return errors.New("PEM certificate invalid format")
	}

	if pemDecoded.Type == PUBPKCS8 {
		parsePublicKey, err := x509.ParsePKIXPublicKey(pemDecoded.Bytes)
		if err != nil {
			return errors.New("Parse publickey certificate failed")
		}

		publicKey = parsePublicKey.(*rsa.PublicKey)
	} else if pemDecoded.Type == PUBPKCS1 {
		parsePublicKey, err := x509.ParsePKCS1PublicKey(pemDecoded.Bytes)
		if err != nil {
			return errors.New("Parse publickey certificate failed")
		}

		publicKey = parsePublicKey
	} else {
		return errors.New("PEM certificate format not supported")
	}

	decodeCipherBodyHash, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return errors.New("Invalid signature format")
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, cipherBodyHash, decodeCipherBodyHash)
	if err != nil {
		return errors.New("Signature not verified")
	}

	return nil
}

func SnapVerifySignature(r *http.Request, req *VerifySignature) error {
	var (
		authorization string = r.Header.Get("Authorization")
		timeStamp     string = strings.TrimSpace(r.Header.Get("X-TIMESTAMP"))
	)

	body, err := json.Marshal(req.Body.(json.RawMessage))
	if err != nil {
		return errors.New("Parse json body failed")
	}

	sha256 := crypto.SHA256.New()
	sha256.Write(body)
	sha256SecretKey := strings.ToLower(hex.EncodeToString(sha256.Sum(nil)))

	headers := SymetricSignatureSnap{}
	headers.Url = strings.TrimSpace(r.URL.Path)
	headers.Method = strings.TrimSpace(strings.ToUpper(r.Method))
	headers.AccessToken = strings.TrimSpace(strings.Split(authorization, "Bearer ")[1])
	headers.ClientSecret = strings.TrimSpace(req.ClientSecret)
	headers.TimeStamp = strings.TrimSpace(timeStamp)

	hmac512Body := headers.Method + ":" + headers.Url + ":" + headers.AccessToken + ":" + sha256SecretKey + ":" + headers.TimeStamp
	hmac512 := hmac.New(crypto.SHA512.New, []byte(headers.ClientSecret))
	hmac512.Write([]byte(strings.TrimSpace(hmac512Body)))

	signatureToken := base64.StdEncoding.EncodeToString(hmac512.Sum(nil))

	if ok := reflect.DeepEqual(req.Signature, signatureToken); !ok {
		return errors.New("Unauthorized. [Invalid Signature]")
	}

	return nil
}
