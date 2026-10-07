# tpm

This package is an abstraction on top of the go-tpm libraries to use a local
TPM to create and use RSA, ECC, AES, and HMAC keys that are bound to that TPM.
The keys can never be used without the TPM that was used to create them.

Any number of keys can be created and used concurrently. The library takes
care loading the right key in the TPM, as needed.

By default, 2048-bit RSA keys are created. AES keys, ECC keys, HMAC keys, and
RSA keys of different sizes can also be created if the TPM supports them.

Keys are created under a storage root key (SRK) in the owner hierarchy, so
clearing the TPM invalidates them. All commands that use keys are protected
by HMAC sessions salted with the SRK: auth values are never sent to the TPM
in cleartext, secret parameters are encrypted, and responses are
authenticated. Serialized keys are bound to the SRK that they were created
under.

The SRK itself is trusted on first use: this package doesn't verify that it
belongs to a genuine TPM (e.g. with the endorsement key's certificate). A
device that impersonates the TPM when a key is created can capture that key's
auth value and parameters. Once a key exists, a different device can't use it,
or complete the sessions that protect it.

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

Saved key: 010022000b3d8e02b755a6bf844c51eb62a9f6aad4d5363aa0f8f504ee31af32ed67e851f202e002de002073f34d6185fb2540c0e25c3c7c1701ba1d577d209b4363d9e86a0f23fd73bb0f001046c597eb180179b1b71973c95409847cfb983ec2bdbeb4c1b3f7f79577ff9e8647412270a3725ec0b3924095e15198754255d366892182e71a77f846b8316c29b83139f547e5c89a4460d222f0d7319e290e166857c09a7b44b0c4e6adac613a69f10d1748f462efe33d158e586ce691497f4e4361106b36201ef36d356f8ebde12de2bd0154f634e5d80ecf272dcf223fea9f21da273079e9eba0fa8061e6e6d4fa3049d45dff89c9deae626da092a6d05320507d5244d96fbb1c7deac0f0a1e8a98545149e6adf12560d3a26ccf19a10bef44e15a2a1460518a6560e0303df0e96f96707a83ab6dbe7cc828cd434de7c95d9bf3b2b355ddb374b477f00c8ba17ef8d4e1b57fc6365149941abaac2d456ea91d7cff8b63266871803bc70658a0dc7b968dabeeddce77fba5c6b2315852ade5011d142ae8bff5d09d9ce7cedaa561c323abb0c8ed0e2918bcbc13b1fdb34e174383630d017a95b0e48abef7b4e944b2fc6fc4e3c84d5d12bba68177afbef818f35a747369829100f6f55986308f3fb619db63291ed75bb435a1acf386ba8ff96f046e3ccc1a87194a2e0c37b7308e774016ed0d9101659e3fb238a9c7e8743b9376843ff549dd7a21933540b31dd7dc1b841400917027f513c27ca619a3ef3532b709bfad32931c6eb54e820e681f29ba669d908ed05ca508d489ced426a7776c7e4822b3322c607314453b5fa5d89b46ce9c653ecb7b50238928bc55983d22519faac2f5fda6afbbc9ebf318d12e8fd5515e3866c3b841212b432ffd1a7445a179c4618b8a962500132b14f52c5b39446fc789ddbe45a07417ea67218a020f509f51bcf0534009dd325daba8ee0ca91337120ba953d71a8dcc0cfe5896c8180175079d4f693ac4137b377e8a8dd86dab16248a446dc49fefaca9484a7122d2baf4e648e7387b2b542c41f3bf47e13e7260aadc3b0b9775406fcebb31e006a79a68f4151ebc767011801160001000b000600720000001000100800000000000100d094d5d76532d5fae8d7b8252007d97f831da2edae73131fa164c4e81b9f9b82618bd7c63d3a2b6b07e97e78b38df3556a98db73e7d1f2f4465061c90a17388abb6cc093d1bfbb216ba8f94be4a116db2f327fa4c3b0d4ce261970c700ce94d4eb0e8972a08c62680487caec35a24a14822f91d1aae80988ca3b4a18a8e15f2b133d7e1de477fec7788c8be1b2ea77a73b869a3ac7457bf4863fcad5a0e7eec80cddd60fe7869827141469ed68054b63babb3976cececf48782d3676b62dcbcf0258bc8a018d8950c0a76fb53a6597a9b1a8893020cbcfc7b0c5ff784e23fbeff66860a6bb862f2c78202d6929dfa7253b282758b6d53ecc30f650a85cc4949b

Payload: "Hello world!"
Encrypted with TPM: bafc3dd90da5986058712675e4d23b8b3aa9e222c20251e0da405a3effca7ea14d76a87b7c5709399f937b4a475523b618910992425b8c17a00221e327664c9f177d47dbf16eb0c1d4d7c6285e326454157f3251c2f34aa49a4fb693938959d5df57cb7f8a5671104cc80ef50b9752ef9ac78faa64bc89e5e6728ed454078b778be2ab9b29f1513ed030e0364bf1506ba170b08238f7aa9e66bec34ba19e340048c5aaa93ebcdd4deab51c6117bd633b8f62a612cfa11f4291e2d300a7d8caa8e94ccc8a6382f98c4fafde5d1c58854adc05673ab8e85ee80f8db2025c3d00060b333c00c92f615791edd60ca419df86923db3acb420dcaaf867edca2cf0c356
Signature: c8b19e81c0452f31ca3316b11c04b86b7aab00dc82d4ca5869d9aa2bd733f240b8b67a21e194a365acd1ab36cedf78c0d548e0f52758ab33ad82cea95e15d3a53d1722c7ca3da33451fc285645219f9fa0d6d2d95264233db18d016e31b20730ee194a0d4b2c955b7ed73c350bcebf20708592023547d8855cca279d7b0ac0e481823c37732712de2ce79fff4b6a6e99ad67cac795f4eb9628010846d34fd38d1a1134d964b7d85ddf95f7eda6475f8ad6a6a1695585b0f7bdc8273c949a69315fe0e942e4071f0dba55adab0a1d03dc9e279429da299f08db3e44f432625f474575cc0beceb344209a94991ee61d4b09fb02266d779b4b80c75d28a2c5e64d9
Verify signature: OK
Decrypted with TPM: "Hello world!"

Encrypted with rsa.EncryptOAEP: 316a2510c0b39b777aec5fcc66531371b1f45c03d4fd64cb06a71f77fc4f4c09124183648b14da1c7c17ffd99e2dbe504bfabd810fd81ec0a4346f9bbe1d81c9b500447eb455e38df2fd21c25c597d2f46b7d676d837deab425979a83318a05247390b1ec418fe3dd93b062b9c85d4bcfdd11fcba0ef93ffd0fc6689e357d11d05905f40680c39bb007f3997b8b9bd94e86e6d193ee4426bb97df2e760c01c79d657a2f8bc358b237a1e18fba44da660a22fba4719d74d30bd39704b7c30e4a105e736e38515e4751fd288e007ecfb788b2da4b8eee27715463afb8e6813c0836ffa20f938bd64c6f7d673da14bd25d951ce0cefbfa50151903293fb868dcbc4
Decrypted with TPM: "Hello world!"
```
