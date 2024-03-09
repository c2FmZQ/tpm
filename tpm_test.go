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
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
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

		tpm.objectAuth = []byte("wrong")
		if _, err := key.Decrypt(nil, enc, nil); err == nil {
			t.Fatal("tpm.Decrypt should have failed")
		}
		tpm.objectAuth = []byte(keyPassphrase)
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
