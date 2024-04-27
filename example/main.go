package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/c2FmZQ/tpm"
	"github.com/google/go-tpm-tools/simulator"
)

func main() {
	sim := flag.Bool("sim", false, "Use TPM simulator")
	flag.Parse()
	var opts []tpm.Option
	if *sim {
		s, err := simulator.Get()
		if err != nil {
			log.Fatalf("simulator.Get: %v", err)
		}
		opts = append(opts, tpm.WithTPM(s))
	}

	tpm, err := tpm.New(opts...)
	if err != nil {
		log.Fatalf("tpm.New: %v", err)
	}
	defer tpm.Close()

	key, err := tpm.CreateKey()
	if err != nil {
		log.Fatalf("tpm.CreateKey: %v", err)
	}
	fmt.Printf("Key type: %s-%d\n\n", key.Type(), key.Bits())
	b, err := key.Marshal()
	if err != nil {
		log.Fatalf("key.Marshal: %v", err)
	}
	fmt.Printf("Saved key: %s\n\n", hex.EncodeToString(b))

	payload := "Hello world!"
	fmt.Printf("Payload: %q\n", payload)

	// Encrypt with the TPM.
	encrypted, err := key.Encrypt([]byte(payload))
	if err != nil {
		log.Fatalf("key.Encrypt: %v", err)
	}
	fmt.Printf("Encrypted with TPM: %s\n", hex.EncodeToString(encrypted))

	hashed := sha256.Sum256(encrypted)
	sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("key.Sign: %v", err)
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(sig))
	if err := rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
		log.Fatalf("rsa.VerifyPKCS1v15: %v", err)
	}
	fmt.Println("Verify signature: OK")

	decrypted, err := key.Decrypt(nil, encrypted, nil)
	if err != nil {
		log.Fatalf("key.Decrypt: %v", err)
	}
	fmt.Printf("Decrypted with TPM: %q\n\n", string(decrypted))

	// Encrypt with [rsa.EncryptOAEP] library.
	encrypted2, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key.Public().(*rsa.PublicKey), []byte(payload), nil)
	if err != nil {
		log.Fatalf("rsa.EncryptOAEP: %v", err)
		return
	}
	fmt.Printf("Encrypted with rsa.EncryptOAEP: %s\n", hex.EncodeToString(encrypted2))

	decrypted2, err := key.Decrypt(nil, encrypted2, nil)
	if err != nil {
		log.Fatalf("key.Decrypt: %v", err)
	}
	fmt.Printf("Decrypted with TPM: %q\n", string(decrypted2))
}
