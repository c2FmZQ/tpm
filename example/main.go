package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log"

	"github.com/c2FmZQ/tpm"
	legacy "github.com/google/go-tpm/legacy/tpm2"
)

const keyPassphrase = "foobar"

func main() {
	rwc, err := legacy.OpenTPM()
	if err != nil {
		log.Fatalf("OpenTPM: %v", err)
	}

	tpm, err := tpm.New(rwc, []byte(keyPassphrase))
	if err != nil {
		log.Fatalf("tpm.New: %v", err)
	}
	defer tpm.Close()

	// CreateKey returns a []byte that can be saved offline.
	keyctx, err := tpm.CreateKey()
	if err != nil {
		log.Fatalf("tpm.CreateKey: %v", err)
	}

	key, err := tpm.Key(keyctx)
	if err != nil {
		log.Fatalf("tpm.Key: %v", err)
	}

	payload := "Hello world!"

	encrypted, err := key.Encrypt([]byte(payload))
	if err != nil {
		log.Fatalf("key.Encrypt: %v", err)
	}
	decrypted, err := key.Decrypt(encrypted)
	if err != nil {
		log.Fatalf("key.Decrypt: %v", err)
	}
	_ = decrypted

	hashed := sha256.Sum256([]byte(payload))
	sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("key.Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
		log.Fatalf("rsa.VerifyPKCS1v15: %v", err)
	}
}
