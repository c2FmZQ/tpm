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

// Package tpm is an abstraction on top of the go-tpm libraries to use a local
// TPM to create and use RSA keys that are bound to that TPM. The private keys
// can never be used without the TPM that was used to create them.
//
// Any number of keys can be created and used concurrently. The library takes
// care loading the right key in the TPM, as needed.
//
// All keys are 2048-bit RSA and non-duplicable.
package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// New returns a new TPM that's ready to use.
func New(rwc io.ReadWriteCloser, passphrase []byte) (*TPM, error) {
	tpm := &TPM{
		rwc:        rwc,
		passphrase: passphrase,
	}

	// Flush any existing transient handles.
	ttpm := transport.FromReadWriter(rwc)
	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 100,
	}.Execute(ttpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability: %w", err)
	}
	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability(Handles): %w", err)
	}
	for _, h := range handles.Handle {
		tpm2.FlushContext{FlushHandle: h}.Execute(ttpm)
	}
	return tpm, nil
}

// TPM uses a local Trusted Platform Module (TPM) device to create and use RSA
// keys that are bound to that TPM. The private keys can never be used without
// the TPM created them.
type TPM struct {
	mu           sync.Mutex
	rwc          io.ReadWriteCloser
	passphrase   []byte
	loadedKey    string
	loadedHandle tpm2.TPMHandle
}

// CreateKey creates a new RSA key and returns a saved TPM context. The TPM
// context can be saved online. Use Key() to use the RSA key tied to the
// context. Any number of keys can be created.
func (t *TPM) CreateKey() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tpm := transport.FromReadWriter(t.rwc)

	unique := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, unique); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	inPubTempl := tpm2.RSASRKTemplate
	inPubTempl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: unique})
	createPrimaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(inPubTempl),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	srk := tpm2.NamedHandle{
		Handle: createPrimaryResp.ObjectHandle,
		Name:   tpm2.TPM2BName{Buffer: []byte("SRK")},
	}
	defer tpm2.FlushContext{FlushHandle: srk}.Execute(tpm)

	unique = make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, unique); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	rsaKeyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: unique,
			},
		),
	}
	createResp, err := tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: t.passphrase,
				},
			},
		},
		InPublic: tpm2.New2B(rsaKeyTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Create: %w", err)
	}

	loadResp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createResp.OutPrivate,
		InPublic:     createResp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Load: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(tpm)

	saveResp, err := tpm2.ContextSave{SaveHandle: loadResp.ObjectHandle}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ContextSave: %w", err)
	}
	savedContext := tpm2.Marshal(saveResp.Context)

	return savedContext, nil
}

// Close closes the connections to the TPM.
func (t *TPM) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.loadedKey != "" {
		tpm := transport.FromReadWriter(t.rwc)
		tpm2.FlushContext{FlushHandle: t.loadedHandle}.Execute(tpm)
		t.loadedKey = ""
		t.loadedHandle = 0
	}
	return t.rwc.Close()
}

// Key returns the Key tied to the saved TPM context.
func (t *TPM) Key(savedContext []byte) (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key, err := tpm2.Unmarshal[tpm2.TPMSContext](savedContext)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unmarshal: %w", err)
	}
	hashed := sha256.Sum256(savedContext)
	out := &Key{
		t:   t,
		id:  hex.EncodeToString(hashed[:]),
		key: *key,
	}
	return out, nil
}

var _ crypto.Signer = (*Key)(nil)

// Key executes the expected RSA operations via the TPM. It implements the
// [crypto.Signer] interface.
type Key struct {
	t         *TPM
	id        string
	key       tpm2.TPMSContext
	publicKey crypto.PublicKey
}

func (k *Key) loadLocked() error {
	if k.t.loadedKey == k.id {
		return nil
	}
	tpm := transport.FromReadWriter(k.t.rwc)
	if k.t.loadedKey != "" {
		tpm2.FlushContext{FlushHandle: k.t.loadedHandle}.Execute(tpm)
		k.t.loadedKey = ""
		k.t.loadedHandle = 0
	}
	contextLoadResp, err := tpm2.ContextLoad{Context: k.key}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("TPM2_ContextLoad: %w", err)
	}
	k.t.loadedKey = k.id
	k.t.loadedHandle = contextLoadResp.LoadedHandle
	if k.publicKey == nil {
		pub, err := k.publicLocked()
		if err != nil {
			return err
		}
		k.publicKey = pub
	}
	return nil
}

func (k *Key) publicLocked() (crypto.PublicKey, error) {
	tpm := transport.FromReadWriter(k.t.rwc)
	readPublicResp, err := tpm2.ReadPublic{ObjectHandle: k.t.loadedHandle}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	outPublic, err := readPublicResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	rsaParms, err := outPublic.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	rsaPubKeyN, err := outPublic.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	rsaPubKey, err := tpm2.RSAPub(rsaParms, rsaPubKeyN)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	return rsaPubKey, nil
}

// Public returns the public key.
func (k *Key) Public() crypto.PublicKey {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil
	}
	return k.publicKey
}

// Sign signs a digest with the RSA key.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}

	hashAlg, err := legacy.HashToAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	scheme := legacy.SigScheme{
		Alg:  legacy.AlgRSASSA,
		Hash: hashAlg,
	}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		scheme.Alg = legacy.AlgRSAPSS
		scheme.Count = uint32(pss.SaltLength)
	}
	sig, err := legacy.Sign(k.t.rwc, tpmutil.Handle(k.t.loadedHandle), string(k.t.passphrase), digest, nil, &scheme)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Sign: %w", err)
	}
	return sig.RSA.Signature, nil
}

// Encrypt encrypts cleartext with the RSA key.
func (k *Key) Encrypt(cleartext []byte) ([]byte, error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	enc, err := legacy.RSAEncrypt(k.t.rwc, tpmutil.Handle(k.t.loadedHandle), cleartext, &legacy.AsymScheme{Alg: legacy.AlgOAEP, Hash: legacy.AlgSHA256}, "")
	if err != nil {
		return nil, fmt.Errorf("TPM2_RSAEncrypt: %w", err)
	}
	return enc, nil
}

// Decrypt decrypts ciphertext with the RSA key.
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	dec, err := legacy.RSADecrypt(k.t.rwc, tpmutil.Handle(k.t.loadedHandle), string(k.t.passphrase), ciphertext, &legacy.AsymScheme{Alg: legacy.AlgOAEP, Hash: legacy.AlgSHA256}, "")
	if err != nil {
		return nil, fmt.Errorf("TPM2_RSADecrypt: %w", err)
	}
	return dec, nil
}
