// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
)

func TestRSA(t *testing.T) {
	const (
		keyPassphrase = "blah"
		payload       = "Hello World!"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc), WithObjectAuth([]byte(keyPassphrase)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	for _, size := range []int{1024, 2048} {
		key, err := tpm.CreateKey(WithRSA(size))
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}

		if got, want := key.Type(), TypeRSA; got != want {
			t.Fatalf("key.Type() = %d, want %d", got, want)
		}
		if got, want := key.Bits(), size; got != want {
			t.Fatalf("key.Bits() = %d, want %d", got, want)
		}
		enc, err := key.Encrypt([]byte(payload))
		if err != nil {
			t.Fatalf("tpm.Encrypt: %v", err)
		}
		dec, err := key.Decrypt(nil, enc, nil)
		if err != nil {
			t.Fatalf("tpm.Decrypt: %v", err)
		}
		if got, want := string(dec), payload; got != want {
			t.Fatalf("Decrypt() = %q, want %q", got, want)
		}

		pub := key.Public()

		// OAEP options are honored.
		label := []byte("label\x00")
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
			enc, err := rsa.EncryptOAEP(h.New(), rand.Reader, pub.(*rsa.PublicKey), []byte(payload), label)
			if err != nil {
				t.Fatalf("rsa.EncryptOAEP: %v", err)
			}
			dec, err := key.Decrypt(nil, enc, &rsa.OAEPOptions{Hash: h, Label: label})
			if err != nil {
				t.Fatalf("tpm.Decrypt(%v, label): %v", h, err)
			}
			if got, want := string(dec), payload; got != want {
				t.Fatalf("Decrypt() = %q, want %q", got, want)
			}
			if _, err := key.Decrypt(nil, enc, &rsa.OAEPOptions{Hash: h, Label: []byte("other\x00")}); err == nil {
				t.Fatal("tpm.Decrypt with wrong label should have failed")
			}
			if _, err := key.Decrypt(nil, enc, &rsa.OAEPOptions{Hash: h}); err == nil {
				t.Fatal("tpm.Decrypt without label should have failed")
			}
		}
		if _, err := key.Decrypt(nil, enc, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("label")}); err == nil {
			t.Fatal("tpm.Decrypt with non-null-terminated label should have failed")
		}
		if _, err := key.Decrypt(nil, enc, &rsa.PKCS1v15DecryptOptions{}); err == nil {
			t.Fatal("tpm.Decrypt with PKCS1v15 options should have failed")
		}

		hashed := sha256.Sum256([]byte(payload))
		sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign(): %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
			t.Fatalf("VerifyPKCS1v15: %v", err)
		}
		pssOptions := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
		sig2, err := key.Sign(nil, hashed[:], pssOptions)
		if err != nil {
			t.Fatalf("Sign(): %v", err)
		}
		if err := rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig2, pssOptions); err != nil {
			t.Fatalf("VerifyPSS: %v", err)
		}

		tpm.objectAuth = []byte("wrong")
		if _, err := key.Decrypt(nil, enc, nil); err == nil {
			t.Fatal("tpm.Decrypt should have failed")
		}
		tpm.objectAuth = []byte(keyPassphrase)
	}
}

func TestECC(t *testing.T) {
	const (
		keyPassphrase = "blah"
		payload       = "Hello World!"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc), WithObjectAuth([]byte(keyPassphrase)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	for _, curve := range []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	} {
		key, err := tpm.CreateKey(WithECC(curve))
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}

		if got, want := key.Type(), TypeECC; got != want {
			t.Fatalf("key.Type() = %d, want %d", got, want)
		}
		if got, want := key.Curve(), curve; got != want {
			t.Fatalf("key.Curve() = %v, want %v", got, want)
		}

		pub := key.Public()
		if got, want := pub.(*ecdsa.PublicKey).Curve.Params().BitSize, curve.Params().BitSize; got != want {
			t.Fatalf("pub.Curve.Params().BitSize = %d, want %d", got, want)
		}
		hashed := sha256.Sum256([]byte(payload))
		sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign(): %v", err)
		}
		if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), hashed[:], sig) {
			t.Fatal("VerifyASN1 failed")
		}
	}
}

func TestAES(t *testing.T) {
	const (
		keyPassphrase = "blah"
		payload       = "Hello World!"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc), WithObjectAuth([]byte(keyPassphrase)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	for _, size := range []int{128, 256} {
		key, err := tpm.CreateKey(WithAES(size))
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}

		if got, want := key.Type(), TypeAES; got != want {
			t.Fatalf("key.Type() = %d, want %d", got, want)
		}
		if got, want := key.Bits(), size; got != want {
			t.Fatalf("key.Bits() = %d, want %d", got, want)
		}
		enc, err := key.Encrypt([]byte(payload))
		if err != nil {
			t.Fatalf("tpm.Encrypt: %v", err)
		}
		dec, err := key.Decrypt(nil, enc, nil)
		if err != nil {
			t.Fatalf("tpm.Decrypt: %v", err)
		}
		if got, want := string(dec), payload; got != want {
			t.Fatalf("Decrypt() = %q, want %q", got, want)
		}

		// Large messages are supported.
		large := bytes.Repeat([]byte("x"), 100000)
		encLarge, err := key.Encrypt(large)
		if err != nil {
			t.Fatalf("tpm.Encrypt(large): %v", err)
		}
		decLarge, err := key.Decrypt(nil, encLarge, nil)
		if err != nil {
			t.Fatalf("tpm.Decrypt(large): %v", err)
		}
		if !bytes.Equal(decLarge, large) {
			t.Fatal("Decrypt(large) mismatch")
		}

		// Any modification of the ciphertext must be detected.
		for i := range enc {
			tampered := slices.Clone(enc)
			tampered[i] ^= 0x01
			if _, err := key.Decrypt(nil, tampered, nil); err == nil {
				t.Fatalf("tpm.Decrypt should have failed with byte %d modified", i)
			}
		}
		if _, err := key.Decrypt(nil, enc[:len(enc)-1], nil); err == nil {
			t.Fatal("tpm.Decrypt should have failed with truncated ciphertext")
		}

		tpm.objectAuth = []byte("wrong")
		if _, err := key.Decrypt(nil, enc, nil); err == nil {
			t.Fatal("tpm.Decrypt should have failed")
		}
		tpm.objectAuth = []byte(keyPassphrase)
	}
}

func TestHMAC(t *testing.T) {
	const (
		keyPassphrase = "blah"
		payload       = "Hello World!"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc), WithObjectAuth([]byte(keyPassphrase)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	// Test HMAC SHA256, SHA384, SHA512
	tests := []struct {
		bits int
		hash crypto.Hash
	}{
		{256, crypto.SHA256},
		{384, crypto.SHA384},
		{512, crypto.SHA512},
	}

	// Default size (SHA256)
	key, err := tpm.CreateKey(WithHMAC(0))
	if err != nil {
		t.Fatalf("tpm.CreateKey: %v", err)
	}
	if got, want := key.Bits(), 256; got != want {
		t.Fatalf("key.Bits() = %d, want %d", got, want)
	}

	for _, tc := range tests {
		key, err := tpm.CreateKey(WithHMAC(tc.bits))
		if err != nil {
			t.Fatalf("tpm.CreateKey(%d): %v", tc.bits, err)
		}

		if got, want := key.Type(), TypeHMAC; got != want {
			t.Fatalf("key.Type() = %d, want %d", got, want)
		}
		if got, want := key.Bits(), tc.bits; got != want {
			t.Fatalf("key.Bits() = %d, want %d", got, want)
		}

		var hashed []byte
		if tc.hash == crypto.SHA256 {
			h := sha256.Sum256([]byte(payload))
			hashed = h[:]
		} else {
			// For simplicity in test, just use empty or simple data,
			// but we should match the hash size to be realistic if needed.
			// Actually Sign() takes a digest, so we should provide a digest.
			h := tc.hash.New()
			h.Write([]byte(payload))
			hashed = h.Sum(nil)
		}

		sig, err := key.Sign(nil, hashed, tc.hash)
		if err != nil {
			t.Fatalf("Sign(): %v", err)
		}

		// HMAC is deterministic. Verify that signing the same data twice produces the same signature.
		sig2, err := key.Sign(nil, hashed, tc.hash)
		if err != nil {
			t.Fatalf("Sign() 2: %v", err)
		}

		if !bytes.Equal(sig, sig2) {
			t.Fatal("HMAC signatures should be deterministic, but they do not match")
		}

		// Test HMAC method on the original payload.
		mac, err := key.HMAC([]byte(payload))
		if err != nil {
			t.Fatalf("key.HMAC: %v", err)
		}

		// HMAC is deterministic. Verify that HMACing the same data twice produces the same MAC.
		mac2, err := key.HMAC([]byte(payload))
		if err != nil {
			t.Fatalf("key.HMAC 2: %v", err)
		}
		if !bytes.Equal(mac, mac2) {
			t.Fatal("HMAC results should be deterministic, but they do not match")
		}

		// The result of HMAC(message) should be different from Sign(hash(message)).
		if bytes.Equal(sig, mac) {
			t.Fatal("key.Sign(hash) and key.HMAC(message) should not produce the same result")
		}

		// Verify encryption/decryption fails
		if _, err := key.Encrypt([]byte(payload)); err == nil {
			t.Fatal("Encrypt should have failed")
		}
		if _, err := key.Decrypt(nil, []byte(payload), nil); err == nil {
			t.Fatal("Decrypt should have failed")
		}
	}

	// Test invalid size
	if _, err := tpm.CreateKey(WithHMAC(511)); err == nil {
		t.Fatal("tpm.CreateKey(511) should have failed")
	}
}

func TestMarshal(t *testing.T) {
	const (
		keyPassphrase = "blah"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc), WithObjectAuth([]byte(keyPassphrase)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	var contexts [][]byte
	var encrypted [][]byte
	for i := 0; i < 10; i++ {
		key, err := tpm.CreateKey()
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}
		b, err := key.Marshal()
		if err != nil {
			t.Fatalf("key.Marshal: %v", err)
		}
		contexts = append(contexts, b)

		payload := []byte(fmt.Sprintf("Payload %d", i))
		enc, err := key.Encrypt(payload)
		if err != nil {
			t.Fatalf("tpm.Encrypt: %v", err)
		}
		encrypted = append(encrypted, enc)

		dec, err := key.Decrypt(nil, enc, nil)
		if err != nil {
			t.Fatalf("tpm.Decrypt: %v", err)
		}
		if got, want := dec, payload; !bytes.Equal(got, want) {
			t.Fatalf("tpm.Decrypt() = %q, want %q", got, want)
		}
	}

	for i := 0; i < 100; i++ {
		ctx := contexts[i%10]
		key, err := tpm.UnmarshalKey(ctx)
		if err != nil {
			t.Fatalf("tpm.UnmarshalKey: %v", err)
		}
		dec, err := key.Decrypt(nil, encrypted[i%10], nil)
		if err != nil {
			t.Fatalf("tpm.Decrypt: %v", err)
		}
		if got, want := dec, []byte(fmt.Sprintf("Payload %d", i%10)); !bytes.Equal(got, want) {
			t.Fatalf("tpm.Decrypt() = %q, want %q", got, want)
		}
	}
}

func TestClearInvalidatesKeys(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := New(WithTPM(rwc))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	key, err := tpm.CreateKey()
	if err != nil {
		t.Fatalf("tpm.CreateKey: %v", err)
	}
	b, err := key.Marshal()
	if err != nil {
		t.Fatalf("key.Marshal: %v", err)
	}
	if _, err := tpm.UnmarshalKey(b); err != nil {
		t.Fatalf("tpm.UnmarshalKey: %v", err)
	}

	tpm.mu.Lock()
	tpm.flushLocked()
	_, err = tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHLockout,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}.Execute(tpm.tpm)
	// TPM2_Clear flushed the SRK.
	tpm.srk = tpm2.NamedHandle{}
	tpm.mu.Unlock()
	if err != nil {
		t.Fatalf("TPM2_Clear: %v", err)
	}

	if _, err := tpm.UnmarshalKey(b); !errors.Is(err, ErrWrongTPM) {
		t.Fatalf("tpm.UnmarshalKey after TPM2_Clear: got %v, want %v", err, ErrWrongTPM)
	}
}

func TestWrongTPM(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpm, err := New(WithTPM(rwc))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := tpm.CreateKey()
	if err != nil {
		t.Fatalf("tpm.CreateKey: %v", err)
	}
	b, err := key.Marshal()
	if err != nil {
		t.Fatalf("key.Marshal: %v", err)
	}
	tpm.Close()

	rwc2, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	other, err := New(WithTPM(rwc2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer other.Close()
	if _, err := other.UnmarshalKey(b); !errors.Is(err, ErrWrongTPM) {
		t.Fatalf("tpm.UnmarshalKey on different TPM: got %v, want %v", err, ErrWrongTPM)
	}
}

// recorder records all the bytes exchanged with the TPM.
type recorder struct {
	io.ReadWriteCloser
	buf bytes.Buffer
}

func (r *recorder) Read(b []byte) (int, error) {
	n, err := r.ReadWriteCloser.Read(b)
	r.buf.Write(b[:n])
	return n, err
}

func (r *recorder) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.ReadWriteCloser.Write(b)
}

func TestBusConfidentiality(t *testing.T) {
	var (
		ownerAuth  = []byte("owner-secret-passphrase")
		objectAuth = []byte("object-secret-passphrase")
		payload    = []byte("very-secret-payload-0123456789")
	)

	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{Buffer: ownerAuth},
	}).Execute(transport.FromReadWriteCloser(sim)); err != nil {
		t.Fatalf("TPM2_HierarchyChangeAuth: %v", err)
	}
	rec := &recorder{ReadWriteCloser: sim}

	tpm, err := New(WithTPM(rec), WithOwnerAuth(ownerAuth), WithObjectAuth(objectAuth))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	for _, opt := range []KeyOption{WithRSA(2048), WithAES(128), WithHMAC(256)} {
		key, err := tpm.CreateKey(opt)
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}
		switch key.Type() {
		case TypeRSA, TypeAES:
			enc, err := key.Encrypt(payload)
			if err != nil {
				t.Fatalf("key.Encrypt: %v", err)
			}
			dec, err := key.Decrypt(nil, enc, nil)
			if err != nil {
				t.Fatalf("key.Decrypt: %v", err)
			}
			if !bytes.Equal(dec, payload) {
				t.Fatalf("key.Decrypt() = %q, want %q", dec, payload)
			}
		case TypeHMAC:
			mac, err := key.HMAC(payload)
			if err != nil {
				t.Fatalf("key.HMAC: %v", err)
			}
			if bytes.Contains(rec.buf.Bytes(), mac) {
				t.Error("HMAC output seen on the bus")
			}
		}
	}

	for _, secret := range [][]byte{ownerAuth, objectAuth, payload} {
		if bytes.Contains(rec.buf.Bytes(), secret) {
			t.Errorf("%q seen on the bus", secret)
		}
	}
}

func TestRejectKnownSensitiveKey(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpm, err := New(WithTPM(rwc))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	// Create an HMAC key under the SRK with a key value chosen by the
	// caller, i.e. a key that isn't secret.
	tpm.mu.Lock()
	srk, err := tpm.srkLocked()
	if err != nil {
		tpm.mu.Unlock()
		t.Fatalf("srkLocked: %v", err)
	}
	createResp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.Handle,
			Name:   srk.Name,
			Auth:   tpm.sessionLocked(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: []byte("attacker-known-key"),
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				SignEncrypt:  true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(
							tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256},
						),
					},
				},
			),
		}),
	}.Execute(tpm.tpm)
	tpm.mu.Unlock()
	if err != nil {
		t.Fatalf("TPM2_Create: %v", err)
	}

	var b cryptobyte.Builder
	b.AddUint8(keyFormatVersion)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(srk.Name.Buffer) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tpm2.Marshal(createResp.OutPrivate)) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tpm2.Marshal(createResp.OutPublic)) })

	if _, err := tpm.UnmarshalKey(b.BytesOrPanic()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("tpm.UnmarshalKey: got %v, want %v", err, ErrInvalidKey)
	}
}

func TestKeyUsage(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpm, err := New(WithTPM(rwc))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	payload := []byte("Hello World!")
	hashed := sha256.Sum256(payload)

	t.Run("RSA signing only", func(t *testing.T) {
		key, err := tpm.CreateKey(WithRSA(2048), WithSigningOnly())
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}
		sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("key.Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
			t.Fatalf("VerifyPKCS1v15: %v", err)
		}
		if _, err := key.Encrypt(payload); !errors.Is(err, ErrKeyUsage) {
			t.Fatalf("key.Encrypt: got %v, want %v", err, ErrKeyUsage)
		}
		enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key.Public().(*rsa.PublicKey), payload, nil)
		if err != nil {
			t.Fatalf("rsa.EncryptOAEP: %v", err)
		}
		if _, err := key.Decrypt(nil, enc, nil); !errors.Is(err, ErrKeyUsage) {
			t.Fatalf("key.Decrypt: got %v, want %v", err, ErrKeyUsage)
		}
		// The TPM enforces it too.
		key.canDecrypt = true
		if _, err := key.Decrypt(nil, enc, nil); err == nil {
			t.Fatal("TPM decrypted with a signing-only key")
		}
	})

	t.Run("RSA decryption only", func(t *testing.T) {
		key, err := tpm.CreateKey(WithRSA(2048), WithDecryptionOnly())
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}
		enc, err := key.Encrypt(payload)
		if err != nil {
			t.Fatalf("key.Encrypt: %v", err)
		}
		dec, err := key.Decrypt(nil, enc, nil)
		if err != nil {
			t.Fatalf("key.Decrypt: %v", err)
		}
		if !bytes.Equal(dec, payload) {
			t.Fatalf("key.Decrypt() = %q, want %q", dec, payload)
		}
		if _, err := key.Sign(nil, hashed[:], crypto.SHA256); !errors.Is(err, ErrKeyUsage) {
			t.Fatalf("key.Sign: got %v, want %v", err, ErrKeyUsage)
		}
		// The TPM enforces it too.
		key.canSign = true
		if _, err := key.Sign(nil, hashed[:], crypto.SHA256); err == nil {
			t.Fatal("TPM signed with a decryption-only key")
		}
		// Only the key's scheme (OAEP) can be used, not raw RSA.
		tpm.mu.Lock()
		_, err = tpm2.RSADecrypt{
			KeyHandle: tpm2.AuthHandle{
				Handle: tpm.loadedHandle,
				Name:   key.name,
				Auth:   tpm.sessionLocked(nil),
			},
			CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: enc},
			InScheme:   tpm2.TPMTRSADecrypt{Scheme: tpm2.TPMAlgRSAES},
		}.Execute(tpm.tpm)
		tpm.mu.Unlock()
		if err == nil {
			t.Fatal("TPM decrypted with a scheme other than the key's scheme")
		}
	})

	t.Run("ECC signing only", func(t *testing.T) {
		key, err := tpm.CreateKey(WithECC(elliptic.P256()), WithSigningOnly())
		if err != nil {
			t.Fatalf("tpm.CreateKey: %v", err)
		}
		sig, err := key.Sign(nil, hashed[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("key.Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), hashed[:], sig) {
			t.Fatal("VerifyASN1 failed")
		}
	})

	t.Run("Unsupported", func(t *testing.T) {
		for _, opts := range [][]KeyOption{
			{WithECC(elliptic.P256()), WithDecryptionOnly()},
			{WithAES(128), WithSigningOnly()},
			{WithAES(128), WithDecryptionOnly()},
			{WithHMAC(256), WithDecryptionOnly()},
		} {
			if _, err := tpm.CreateKey(opts...); err == nil {
				t.Errorf("tpm.CreateKey should have failed")
			}
		}
	})
}
