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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

func TestTPM(t *testing.T) {
	const (
		keyPassphrase = "blah"
		payload       = "Hello World!"
	)

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("failed to initialize simulator: %v", err)
	}

	tpm, err := New(rwc, []byte(keyPassphrase))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tpm.Close()

	keyctx, err := tpm.CreateKey()
	if err != nil {
		t.Fatalf("tpm.CreateKey: %v", err)
	}

	key, err := tpm.Key(keyctx)
	if err != nil {
		t.Fatalf("tpm.Key: %v", err)
	}

	enc, err := key.Encrypt([]byte(payload))
	if err != nil {
		t.Fatalf("tpm.Encrypt: %v", err)
	}
	dec, err := key.Decrypt(enc)
	if err != nil {
		t.Fatalf("tpm.Decrypt: %v", err)
	}
	if got, want := string(dec), payload; got != want {
		t.Fatalf("decrypt() = %q, want %q", got, want)
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

	tpm.passphrase = []byte("wrong")
	if _, err := key.Decrypt(enc); err == nil {
		t.Fatal("tpm.Decrypt should have failed")
	}
}
