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
```

```sh
$ go run ./example --sim
Key type: RSA-2048

Saved key: 02e002de0020dd5702c97c8bc5c59cfb5ecfb8c193092738c9a648814206b2257db1616bfa090010c0aa1d491afccbd61604980c3bdcf09a3bb520bf95f067f24a73ebfe201dbcd7fd7b6527419a7279d6bc34eb1438929b16a6cee8b7fe0fa326dbb5cbbce18b428d8fe688da83385b6fb0d0dbe9b7ce389169dfaa218cef452c6a4ec39887f1a889513542105aadac781c37a56056c8950417698f5d890d2c2815378311c242aff2c6cdbb8d293c8eb854dc974287e0525256f2bbb406838b34178a9a5165d3b5e6ed56a1c32349bdf140f91fae960d9c0ec6d571986e94efc02ba8b7516e2f345754323ee0b17536127eae7025e8c4573dcac585d32bff2612cdc04b333e91aa8b027db8cafe269a645e6390228fd2e5413d40663e90e485dc14dc0b2938fb1b7b6649343dc509f0935eee2dbf957d7d0383889e68a5ff9ff6cc6bc944bc2b68645b36c00f4d34f10c5467bbb3253028495b4393c133b294c630095dd90af669800ccc824f38d894193d613687b47d64a3906aa0eff579d758f5216dd68e13066d31f7318bc0f186e5b7b82109585c78c2b79515669674bb657845824aaa1980f41948c68ddcf367e3a6861f6c380e7103b4d0c9efdc2c4d603965039841bccf204d7d117b4e2018d6304a451cd31a7d96a6c4f909ac0ac629941f45735e6aec7d9d6e4bfe9a6e8cdacc588eda02a0314b199a8548b7fed72e3fe160c09c87b4328f57cc5eb0cfa1686b3b2dfc7678238e9e686e37ea95ac993153078dc3f854fbaaf36025e241ab0f9bda9ae643523e3f142c2d6c80df87922daa080bfd295796e27e73e65c5351286475f73e68a365c3c466aa586bd63a53288a857b1311ad57f6c91adcc38b1984a2478f38f57bd45d256bc42bf25a04b13705c30a58f99370ad258e512aeeaa31e8ad465c7b6d3132e1d65f1bb184b66e352118f3e702e35ce0eff9c5368c47da007213143659447b0f5b911948e66d0b5a96c92152a2416d0f39d72db434146417561733638edc412706b44c5b8dec2668011801160001000b000600720000001000100800000000000100c1eb6d8227a6496320fb38146f585c4ec5445ffb2cd98686934e26d4913d47c6ace469f9c6ec421878ca13369a008b609889eb084f9a5b93ed82eebdad82487dbad04ed4f0dd4f7bd2efd7832103b29a4ce23810c53327c9c836d61b27e8bfc63a3b1652be6b71a9f112783b9654eb90e0c7b13d7616a64cbd7c50b9526a9ca629875d06903a21d8d0f37b902739ef4bc1a43e41331daa129cbddd6a5c260775b8a5dc73fc1cbb25a689aaa366b88af8d2f51c2c96871dfb0d6bfb1b2353dae8c0ba9783a7ea36421fa1870fe1f47a98781e296ebd65b723dbe9c6e48c6753d9b3f9502ff8f7ca490cac746a52131cbf4a86985a5c4dad03fb50e42c0d7e46a9

Payload: "Hello world!"
Encrypted with TPM: b8f3d8181fdb13950f76af65f7641c944e346e6b9cb5729426fb5eb0786350e3a77148c051c80386ecd1e3f3a9b51df3f741877872609b65160a56188f2d40981fbd663f896b7939263b0156a2b023cab6c9bbb2dae1283b9e89ad66aab628d3333bc99d0e00227161a39e10ad2ff56a9ff6366e2f17bc720d48641944d62c1cf9ff36bef75661175cd92b0af1b11f0845d4053f0409110009911fe438ca4c6e71f56e2246ceb998d91718d979a7d46ee931345a2e530a327b51add1d52aa34b58a984a54cebfb66a98222e161b6967d29e94b0f680a650b9a05f34fc52430030a1bd9019d224173477c6962e889ee9ab3d33424919dc8fcf985f2b80ff59aea
Signature: 7b13438f77557a3bd5bb7d732e949c526bfd9d3ba0e8a3b782fe7d07559c429943bf0c2048d699f8ab9f7b45ecffa5d32cb5537d1aafe81b14f2f44ab8aa5b7aa94e3d61aed0c3fd19d32c66c0eb58112fe8453a111cca0bbdc3895eb21576b1e2b237ef7825eb9fab8c10fb2d124c1ce8f7ef8f32e8d12519c2da3cd34268336d26b0a15b0db28d8301e57b5a0db7ad25b857753b6d83edac5e38077d5fed3c30a5d09fd34c5ca9c02c7f867ac0209b84c1b815f4b85979f6357d4ff19540176a77aa52a62d8588a8254914ce09cab692573f91a50c73238dfe009d069ba3d595c1eb7c93297c4f0c3aa02b779d880b3065d4ffd93dfd4b870d915ac010b1f1
Verify signature: OK
Decrypted with TPM: "Hello world!"

Encrypted with rsa.EncryptOAEP: 37057d43cccdf5b0155db7c14c2641cb0e4d58c021a31dcd098f548f3eddfb9217024031ee232cd5c7618996c15e99df69132ff2a7cc4974878ad369d0f26db72758a91f587799ca4826d3826927f4626e937a1566e861919175328a9b6b9d3bcd8ddc7a6e0222cd15dc49a3abf9b423c143fb1b27e9072e57967f5653d6e2d224d14a16812b75584f2e7313cf69cab4cfbf527f8e9480095eb65ca929573e0de8c4dc06e6ad0170694491c9d02bd0a16b299219be317063d2fdc6102e157d109b8369c39d5f1cbb64a42b6dd3627bba4c044869d396269afb6bca503e2a9f3ef65cf3ab5a4d9d463e3488963c370cf3a95094b26ab215db064a7dbfca95d220
Decrypted with TPM: "Hello world!"
```
