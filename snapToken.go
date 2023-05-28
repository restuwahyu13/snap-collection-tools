package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"strings"
)

type (
	SnapTokenReq struct {
		PrivateKey string `json:"privateKey"`
		TimeStamp  string `json:"timeStamp"`
	}

	AsymmetricSignatureSnap struct {
		PrivateKey string `json:"privateKey,omitempty"`
		PublicKey  string `json:"publicKey,omitempty"`
		TimeStamp  string `json:"timeStamp,omitempty"`
		ClientKey  string `json:"clientKey"`
	}

	SymetricSignatureSnap struct {
		Url          string      `json:"url"`
		Method       string      `json:"method"`
		AccessToken  string      `json:"accessToken"`
		TimeStamp    string      `json:"timeStamp,omitempty"`
		ClientSecret string      `json:"clientSecret"`
		Body         interface{} `json:"body"`
	}

	InterfaceSnapToken interface {
		SnapAsymmetricSignature(req *AsymmetricSignatureSnap, password string) (interface{}, error)
		SnapSymmetricSignature(req *SymetricSignatureSnap) (interface{}, error)
	}

	structSnapToken struct {
		*SnapTokenReq
	}
)

func NewSnapToken(req *SnapTokenReq) InterfaceSnapToken {
	return &structSnapToken{SnapTokenReq: req}
}

func (h *structSnapToken) SnapAsymmetricSignature(req *AsymmetricSignatureSnap, password string) (interface{}, error) {
	salt := rand.Reader
	rsaPrivateKey := new(rsa.PrivateKey)

	headers := AsymmetricSignatureSnap{}
	headers.TimeStamp = h.TimeStamp
	headers.PrivateKey = h.PrivateKey
	headers.ClientKey = req.ClientKey

	cipherBody := []byte(headers.ClientKey + "|" + headers.TimeStamp)
	cipherBodyHash256 := sha256.New()
	cipherBodyHash256.Write(cipherBody)
	cipherBodyHash := cipherBodyHash256.Sum(nil)

	pemDecode, _ := pem.Decode([]byte(headers.PrivateKey))
	if pemDecode == nil {
		return nil, errors.New("Decode credentials certificate failed")
	}

	switch pemDecode.Type {
	case PRIVPKCS1:
		if password != "" && x509.IsEncryptedPEMBlock(pemDecode) {
			pemBlockDecrypt, err := x509.DecryptPEMBlock(pemDecode, []byte(strings.TrimSpace(password)))
			if err != nil {
				return nil, err
			}

			parsePrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlockDecrypt)
			if err != nil {
				return nil, err
			}

			rsaPrivateKey = parsePrivateKey
		}

		parsePrivateKey, err := x509.ParsePKCS1PrivateKey(pemDecode.Bytes)
		if err != nil {
			return nil, err
		}

		rsaPrivateKey = parsePrivateKey

		break

	case PRIVPKCS8:
		if password != "" && x509.IsEncryptedPEMBlock(pemDecode) {
			pemBlockDecrypt, err := x509.DecryptPEMBlock(pemDecode, []byte(strings.TrimSpace(password)))
			if err != nil {
				return nil, err
			}

			parsePrivateKey, err := x509.ParsePKCS8PrivateKey(pemBlockDecrypt)
			if err != nil {
				return nil, err
			}

			rsaPrivateKey = parsePrivateKey.(*rsa.PrivateKey)
		}

		parsePrivateKey, err := x509.ParsePKCS8PrivateKey(pemDecode.Bytes)
		if err != nil {
			return nil, err
		}

		rsaPrivateKey = parsePrivateKey.(*rsa.PrivateKey)

		break

	default:
		return nil, errors.New("Credentials certificate format not supported")
	}

	if err := rsaPrivateKey.Validate(); err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(salt, rsaPrivateKey, crypto.SHA256, cipherBodyHash)
	if err != nil {
		return nil, err
	}

	if err := rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, cipherBodyHash, signature); err != nil {
		return nil, err
	}

	snapAsymmetricSignature := base64.StdEncoding.EncodeToString(signature)
	return snapAsymmetricSignature, nil
}

func (h *structSnapToken) SnapSymmetricSignature(req *SymetricSignatureSnap) (interface{}, error) {
	body := req.Body.([]byte)

	sha256 := crypto.SHA256.New()
	sha256.Write(body)
	sha256SecretKey := strings.ToLower(hex.EncodeToString(sha256.Sum(nil)))

	headers := SymetricSignatureSnap{}
	headers.Url = req.Url
	headers.Method = strings.ToUpper(req.Method)
	headers.AccessToken = req.AccessToken
	headers.ClientSecret = req.ClientSecret
	headers.TimeStamp = req.TimeStamp

	hmac512Body := headers.Method + ":" + headers.Url + ":" + headers.AccessToken + ":" + sha256SecretKey + ":" + headers.TimeStamp
	hmac512 := hmac.New(crypto.SHA512.New, []byte(headers.ClientSecret))
	hmac512.Write([]byte(strings.TrimSpace(hmac512Body)))

	snapSymmetricSignature := base64.StdEncoding.EncodeToString(hmac512.Sum(nil))
	return snapSymmetricSignature, nil
}
