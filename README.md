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
	fmt.Printf("Key context: %s\n\n", hex.EncodeToString(b))

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

Key context: 0000000000000001800000004000000b054e004084df5877bbf9db0a467267e17d0a5afed44e0865213b5ae7f3e32eb7dacb68e8142d97d8fd40e19ed9d62d70129e5de03b770bb7e668a36802c4102927b469c4e46a09cd32d956a3938984873395b668bd9ccba0b975636eb0cce99d635081dd0f894d41c401f0d22f2c789be0b1296cee009210018aeeda9276f555728a35ad517167b6b561ed62c97f4b6126b321a48282917d7f61e26df3f3b9a98196988a5beb0eb4e3d5d8c042b05344b7d23c1b290f7e6e1bcfd6dabcd7dd89f234c451e918363af30ee43119ec4a1888b21059519b69bd3143794e7bbc59e002eb6c69523299e683eb24905aa9f1144ab9ff948033b2f8cd2bad386e75ec99e59a0377e4a380498d44898541c511eab6ef2f6dc16d374e0f11025ab4b96d22d2fa396e51d74bbe69704c2e0f5d22b73983cc62a7d0fdae4b129b1a0cc4154a1d0dad1efce1696695060f2ecc2803553f759a4aedfe3734f6eaf1c05686f69b977afbbc9caba2f795eae451113230f035622bfc9f70c53990507501711cb3d5931ea7f53da0e75530c4149ac3ca126f0aefe45b408d8837f5eddfb06f80ec4ed99d2da895f067394b7c7be8d2c2b2b5a88ccc3f93d60806285ac2567a7e34ae49dd90ca2fb0b7eb573f59047a46ef530fbc6ce05fc790a916b69f0edeacc5aed41f570b7a4c51f6ca95655bfc089cbeec24055cb21abe8eb5905663b72498f498d09b68d51ed2377bd17fd97d2430a479f895a668c6b256132cf15cec639d8262ef573c0f66a9ee50d8b51b3eaf149bf46aa643e71bfeb36589e1ab49193bd66d69049dd1cc85e96de14a4d3ddd0197caa08cfc78d6bd74b74e6b1400b24d2d4ff5e51dc53f543a0dad70c419f2299abae2b68c45f1def394508f3172aa462b4be1f80654cfc7ac151ba5f41a4ff161755a07e76307cb7db6c5798dcbe474f21cbb2999993efe7d8fe83e82b14f1f0b4013e47e06060f4b2cac8289104fa77759ca90694304208c7260f48a0f92e83c799790daa51cb7866b81b59120d700044f187c334c01acd0556ab0f055f92714e204716d4c0fa5161496cd1ab2bcea2c2654ea3ba749ec6cc8dfa716b8a352815ca792ab36438edd44e1c80dbe8fd47a68f3934979124b73ea6ddebe02fb2bb646e973af363222db9ef8ba1ea9557a075d1796405f5150b1e3c7fd7173a0c2f03bf53b56b3b107a09c6430b43e56187e1a2151203d8f20bd378553874f54557d8e2aa9974548df0dbf79a2dc64a0683be3ef1da6fa39fe98a97daeea1eb008f0faefad96420e78affd0aee6457c4992e40507b372bba5a42b3af986d58c4a83cfd9f337873a4c602b5ee4a4e46f567813eccf77a4cdf983c60238953ccdf6bd00a853c041a5b36f854a29ef21506bf4fe9f89735746eb212c5ff92cae871c6ea37dbe0e1032e6e0d4e1996dfd4bc7d45cc10ee3f6cbab9c152ccef0cd1e80c7775a1364c3c7d133167017b717bf23fca05fc3f91db1d9f37437b64ab674d7ed7980bd7bee76a74b6378e23d40eaf7ad6342642b3f4ffd66913132ae0255080f4f9a77f6e56ce9725d9ebaad08c34075369974295be126467a87a0a4b261612637fc6ec74957677c6eb43c651c6f4986ebf8d0b44790a3e9e172e7d15e5285d5be4c2d4773d5de9207d5ab8d87c66b078b22b98293264677a30e168700fefd92c4266c1c9575d1d20da58115d9f5bd914e1fcb2bb24773746ed42adc943788dde5e8eee60bb3bd6219dd6d43bd0c5f58b8e6b09cdcc6a9f5c9341eba5f49526016146d44503cf5d43bece91fc0378133e6ccf730c63198f43fc0c418304965fd2ad367446ed85bd85581238878af16dee65010ba5c8e28ca1e6de9e5dd8a0efb71f8449aa679b5f4ee355ea031eb15b333daf43d97f7d766d5d59f0efa25a1e65

Payload: "Hello world!"
Encrypted with TPM: 3984decf0328d14fdead4016f992f074464e24870672f690d59667f535330ad13287a922a93d817cecb449e874c08f684a1f191b5a7143c54af0f08879891ccaa3a3da84bd0184459cdb4bd33f359671c0dd9c19dc8811e34e9bccd8339d9707c7ac5db3f0e2757dbcfe9d4655d6ff56d0f9189a4edb3928bea2cab9c9bb58d66d1a9d48803d361477944ed5eecc7e822a63bce1ee4631d1e29af3d270c3a27800f9ac08dd6ad8e89288b622c1d4707959070701b1019db55a9bed34460c8f9af0e225f614c7f12c98fea8dc774ca2eb12f2f7c49f0fc2d5700ab8fa29e77e3b7f6953ddbda73726bcf6c8d87d66d6c8c5f451c22841efbba76b17ddf235cc71
Signature: 3208070833f3a36a95516417003ddd5a039cba09b52de27a2b12a0a8c030f3890d464c157f91208dfc9e8ae5cc0f02a738d5cba4e3699ebb8363d75fadb23ad35cf139b8afe0cd962f9db30ae4f9845be221c89a06c97524fffd3c1aea5d41c26a78ff27af0e3dd9966f64a06286beebe2f32e0810abbe3abc852a7145f2f969b5a56812fced5ff912a51dd3d854f40e6462992f06a1c5ffb832e09e32ecefb9729229f4d454ee1dd1ca087714fc193dbf2157d66986839f8b520e7c327b3887e643fd3d2de1e0151ae14ce27c4e67aef27250682e023b4e16e571824ceecbe84cc81a108f3fcdd9069dc34d63d8d39dfcb133701b049a84b604a2262ebdd3e4
Verify signature: OK
Decrypted with TPM: "Hello world!"

Encrypted with rsa.EncryptOAEP: 36a4ffca30d748cc30febae40bfc54243481a3b1c37d020306c9fc3c4018174fc7d2ba557f38ba569f9a98b5668022df79a378e7c867b5a3368ff13e002304bce0d73bf1bd4710c45d5798c595792cc1ce2852741fc359cdd5766b796550d2d19ccd125ef6ce7898de3b5c8f6df5e34bad6fda9161bab53a123c88e070a41ba293c5e99b6dd04d8b1a25b7f74119484be9824778f70671e507ca0b201af37251b07d333f2d10e7fffa8362f6dcbbe210f154bcc55c57690487440ef2800848a9ad860736c77252d318f825f157cbec342f13fd71a231dffd4cb761aa9579a237d0eecd91aabf4e616ec88410394208f366bd9b7c71ff05e827f869398a0d4aec
Decrypted with TPM: "Hello world!"
```
