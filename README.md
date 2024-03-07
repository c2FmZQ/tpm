# tpm

This package is an abstraction on top of the go-tpm libraries to use a local
TPM to create and use RSA, ECC, and AES keys that are bound to that TPM. The
keys can never be used without the TPM that was used to create them.

Any number of keys can be created and used concurrently. The library takes
care loading the right key in the TPM, as needed.

By default, 2048-bit RSA keys are created. AES keys, ECC keys, and RSA keys of
different sizes can also be created if the TPM supports them.

## Example:

```go
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

	// CreateKey returns a []byte that can be saved offline.
	keyctx, err := tpm.CreateKey()
	if err != nil {
		log.Fatalf("tpm.CreateKey: %v", err)
	}

	key, err := tpm.Key(keyctx)
	if err != nil {
		log.Fatalf("tpm.Key: %v", err)
	}
	fmt.Printf("Key type: %s-%d\n", key.Type(), key.Bits())

	payload := "Hello world!"
	fmt.Printf("Payload: %s\n", payload)

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
	fmt.Println("Signature: OK")

	decrypted, err := key.Decrypt(nil, encrypted, nil)
	if err != nil {
		log.Fatalf("key.Decrypt: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", string(decrypted))

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
	fmt.Printf("Decrypted: %s\n", string(decrypted2))
}
```

```sh
$ go run ./example --sim
Key type: RSA-2048

Payload: "Hello world!"
Encrypted with TPM: ca6482623165e3b50da8c683eb2bbdb509c35edaac51a8b81a078b84d1ef869727c7bb11773fb0b36f7120de0fbc745a1c6e92640cc885f00b7c444a4ce8ed070c0369dc84f54b56d4ee9ecd46dd6b0d94d0a167b0503bd7903a2c31c51973ad3022c71c2c499729d84c0f7451194637d08021c3fd109f51a4db0e4b9de6ce51536c9bd923b76d923a967619d9efc95a141a52b216550d5f60e08fd58e7c1784bb82d90dc8ba1bc41fd42d2ddf1c71d3f7846a9f2638a5e722f6eb8ae5525eab80d5e1bce5dc8ffc6b7e9a0869d5152292d979d0d9e4b8dc29187c37bc93d4349b84dd782be7f213c72c69906ef2ca481046f24b172693dac4e28faef5247dab
Signature: 5f81ad25c23d212f3111cfd10d6700a4879a17e8aa470638bda679fbe64c0a5dd9956a0c55340605990d240131e6040dd8064a63dd474260d1cf17513e625a89b9f755ac5fa69b3d598f8aaf59ca5f253cefba41bcbdbf4992b07854885d3664c2ef48fad41f4bd9f08607bd27c2bebe412037c4f37ef54371dd2074da0db44dfeff194db4f89b4bfee980258f283049a57dcba9a9497fd95a460e1b2495b72c81c9384d6f0accad67305b46289b4bbea47589d9b57885f7e907229b55df525cbbd877f77801e2e332e3e91dfd30b92b954e8d52ebeb43c162700373adb9b73e7062e0fc6a143d34178a0fc8657146c20ebe5446f907b9a0993e525e49991689
Verify signature: OK
Decrypted with TPM: "Hello world!"

Encrypted with rsa.EncryptOAEP: 16fd765858df9dac2674c880f353509c4fdd72c150bc62febddbd6561c4b3e9be534335a00f556d91bcbc64652e0b9dafee7e2fc940c84d75af572799dc5e64ac98a535e4ed3a4e56689a760c7649755976adb56eab31f52c5b44166083ecdcdf0c5192a9024e865aefe68407210e5234958269ada77d4fd50331229e0a3377ff2d2a601edaa67442ba4972cc6dd82f0226765c7d70bdef30571a6c056de29c04527ded51ce74a8bc8cd66e8c563419f0d49c7af32ab4bab3ffe774da751b47cd45e1f7b7a15023d0d8defb186ce80b868de9eb66b44231e5f258af01ba489379870c13cebeaa93b5f5e527cfb6fda6480ac302180c0136b35ee7f140ccc7d86
Decrypted with TPM: "Hello world!"
```
