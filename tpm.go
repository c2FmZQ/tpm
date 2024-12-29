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
// TPM to create and use RSA, ECC, and AES keys that are bound to that TPM. The
// keys can never be used without the TPM that was used to create them.
//
// Any number of keys can be created and used concurrently. The library takes
// care loading the right key in the TPM, as needed.
//
// By default, 2048-bit RSA keys are created. AES keys, ECC keys, and RSA keys
// of different sizes can also be created if the TPM supports them.
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	TypeRSA KeyType = 1
	TypeECC KeyType = 2
	TypeAES KeyType = 3
)

var (
	ErrWrongKeyType = errors.New("operation not implemented with this key type")
	ErrInvalidCurve = errors.New("invalid curve id")
	ErrDecrypt      = errors.New("decryption error")
)

type KeyType int

func (t KeyType) String() string {
	switch t {
	case TypeRSA:
		return "RSA"
	case TypeECC:
		return "ECC"
	case TypeAES:
		return "AES"
	default:
		return ""
	}
}

// Option is an option that can be passed to New.
type Option func(*TPM)

// WithTPM specifies an already open TPM device to use.
func WithTPM(rwc io.ReadWriteCloser) Option {
	return func(t *TPM) {
		t.tpm = transport.FromReadWriteCloser(rwc)
	}
}

// WithEndorsementAuth specifies the endorsement passphrase.
func WithEndorsementAuth(pp []byte) Option {
	return func(t *TPM) {
		t.endorsementAuth = slices.Clone(pp)
	}
}

// WithObjectAuth specifies the passphrase to set on created keys.
func WithObjectAuth(pp []byte) Option {
	return func(t *TPM) {
		t.objectAuth = slices.Clone(pp)
	}
}

// New returns a new TPM that's ready to use.
func New(opts ...Option) (*TPM, error) {
	var tpm TPM
	for _, o := range opts {
		o(&tpm)
	}
	if tpm.tpm == nil {
		t, err := linuxtpm.Open("/dev/tpmrm0")
		if errors.Is(err, os.ErrNotExist) {
			t, err = linuxtpm.Open("/dev/tpm0")
		}
		if err != nil {
			return nil, err
		}
		tpm.tpm = t
	}

	// Flush any existing transient handles.
	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 100,
	}.Execute(tpm.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability: %w", err)
	}
	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability(Handles): %w", err)
	}
	for _, h := range handles.Handle {
		tpm2.FlushContext{FlushHandle: h}.Execute(tpm.tpm)
	}
	return &tpm, nil
}

var _ io.Closer = (*TPM)(nil)

// TPM uses a local Trusted Platform Module (TPM) device to create and use
// cryptographic keys that are bound to that TPM. The keys can never be used
// without the TPM created them.
type TPM struct {
	mu              sync.Mutex
	tpm             transport.TPMCloser
	objectAuth      []byte
	endorsementAuth []byte
	loadedKey       string
	loadedHandle    tpm2.TPMHandle
}

type keyOptions struct {
	keyType KeyType
	bits    int
	curve   elliptic.Curve
}

// KeyOption is an option that can be passed to CreateKey.
type KeyOption func(*keyOptions)

// WithRSA indicates that an RSA key should be created.
func WithRSA(bits int) KeyOption {
	return func(opts *keyOptions) {
		opts.keyType = TypeRSA
		opts.bits = bits
		opts.curve = nil
	}
}

// WithECC indicates that an ECC key should be created.
func WithECC(curve elliptic.Curve) KeyOption {
	return func(opts *keyOptions) {
		opts.keyType = TypeECC
		opts.bits = 0
		opts.curve = curve
	}
}

// WithAES indicates that an AES key should be created.
func WithAES(bits int) KeyOption {
	return func(opts *keyOptions) {
		opts.keyType = TypeAES
		opts.bits = bits
		opts.curve = nil
	}
}

// CreateKey creates a new key that's ready to use. Keys can be serialized and
// stored offline with [Key.Marshal], and restored with [TPM.UnmarshalKey]. The
// serialized keys can only be restored using the same TPM.
func (t *TPM) CreateKey(opts ...KeyOption) (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, err := t.createLocked(opts...)
	if err != nil {
		return nil, err
	}
	return t.unmarshalLocked(b)
}

func (t *TPM) createLocked(opts ...KeyOption) ([]byte, error) {
	opt := keyOptions{
		keyType: TypeRSA,
		bits:    2048,
	}
	for _, o := range opts {
		o(&opt)
	}
	t.flushLocked()

	srk, flush, err := t.srk()
	if err != nil {
		return nil, err
	}
	defer flush()

	var public tpm2.TPMTPublic

	switch opt.keyType {
	case TypeRSA:
		unique := make([]byte, opt.bits/8)
		if _, err := io.ReadFull(rand.Reader, unique); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		public = tpm2.TPMTPublic{
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
					KeyBits: tpm2.TPMKeyBits(opt.bits),
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: unique,
				},
			),
		}

	case TypeECC:
		unique := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, unique); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		var curve tpm2.TPMECCCurve
		var hash tpm2.TPMAlgID
		switch opt.curve {
		case elliptic.P224():
			curve = tpm2.TPMECCNistP224
			hash = tpm2.TPMAlgSHA256
		case elliptic.P256():
			curve = tpm2.TPMECCNistP256
			hash = tpm2.TPMAlgSHA256
		case elliptic.P384():
			curve = tpm2.TPMECCNistP384
			hash = tpm2.TPMAlgSHA384
		case elliptic.P521():
			curve = tpm2.TPMECCNistP521
			hash = tpm2.TPMAlgSHA512
		default:
			return nil, ErrInvalidCurve
		}
		public = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: hash,
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
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: curve,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: unique[:32]},
					Y: tpm2.TPM2BECCParameter{Buffer: unique[32:]},
				},
			),
		}

	case TypeAES:
		unique := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, unique); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		public = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
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
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(opt.bits)),
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPM2BDigest{Buffer: unique},
			),
		}
	default:
		return nil, ErrWrongKeyType
	}

	createResp, err := tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: t.objectAuth,
				},
			},
		},
		InPublic: tpm2.New2B(public),
	}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Create: %w", err)
	}

	priv := tpm2.Marshal(createResp.OutPrivate)
	pub := tpm2.Marshal(createResp.OutPublic)

	buf := cryptobyte.NewBuilder(nil)
	buf.AddUint16(uint16(len(priv)))
	buf.AddBytes(priv)
	buf.AddUint16(uint16(len(pub)))
	buf.AddBytes(pub)

	return buf.Bytes()
}

// Close closes the connections to the TPM.
func (t *TPM) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushLocked()
	return t.tpm.Close()
}

func (t *TPM) flushLocked() {
	if t.loadedKey != "" {
		tpm2.FlushContext{FlushHandle: t.loadedHandle}.Execute(t.tpm)
		t.loadedKey = ""
		t.loadedHandle = 0
	}
}

// UnmarshalKey returns the Key associated with serialized data.
func (t *TPM) UnmarshalKey(b []byte) (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unmarshalLocked(b)
}

func (t *TPM) unmarshalLocked(in []byte) (*Key, error) {
	in = slices.Clone(in)
	hashed := sha256.Sum256(in)

	str := cryptobyte.String(in)
	var sz uint16
	var savedPriv []byte
	if !str.ReadUint16(&sz) || !str.ReadBytes(&savedPriv, int(sz)) {
		return nil, errors.New("parse error")
	}
	var savedPub []byte
	if !str.ReadUint16(&sz) || !str.ReadBytes(&savedPub, int(sz)) {
		return nil, errors.New("parse error")
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](savedPriv)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unmarshal: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](savedPub)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unmarshal: %w", err)
	}

	out := &Key{
		t:    t,
		id:   hex.EncodeToString(hashed[:]),
		priv: *priv,
		pub:  *pub,
		keyb: in,
	}
	if t.loadedKey == out.id {
		t.flushLocked()
	}
	if err := out.loadLocked(); err != nil {
		return nil, err
	}
	return out, nil
}

var _ crypto.Decrypter = (*Key)(nil)
var _ crypto.Signer = (*Key)(nil)

// Key performs cryptographic operations via the TPM. It implements the
// [crypto.Signer] and [crypto.Decrypter] interfaces.
type Key struct {
	t         *TPM
	id        string
	priv      tpm2.TPM2BPrivate
	pub       tpm2.TPM2BPublic
	keyb      []byte
	keyType   KeyType
	bits      int
	curve     elliptic.Curve
	publicKey crypto.PublicKey
}

func (k *Key) loadLocked() error {
	if k.t.loadedKey == k.id {
		return nil
	}
	k.t.flushLocked()

	srk, flush, err := k.t.srk()
	if err != nil {
		return err
	}
	defer flush()

	loadResp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    k.priv,
		InPublic:     k.pub,
	}.Execute(k.t.tpm)
	if err != nil {
		return fmt.Errorf("TPM2_Load: %w", err)
	}

	k.t.loadedKey = k.id
	k.t.loadedHandle = loadResp.ObjectHandle
	if k.publicKey == nil {
		if err := k.getPublicLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (k *Key) getPublicLocked() error {
	readPublicResp, err := tpm2.ReadPublic{ObjectHandle: k.t.loadedHandle}.Execute(k.t.tpm)
	if err != nil {
		return fmt.Errorf("TPM2_ReadPublic: %w", err)
	}
	outPublic, err := readPublicResp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("TPM2_ReadPublic: %w", err)
	}

	switch tpm2.TPMAlgID(outPublic.Type) {
	case tpm2.TPMAlgRSA:
		rsaParms, err := outPublic.Parameters.RSADetail()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		rsaPubKeyN, err := outPublic.Unique.RSA()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		rsaPubKey, err := tpm2.RSAPub(rsaParms, rsaPubKeyN)
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		k.publicKey = rsaPubKey
		k.keyType = TypeRSA
		k.bits = int(rsaParms.KeyBits)

	case tpm2.TPMAlgECC:
		eccParms, err := outPublic.Parameters.ECCDetail()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		c, err := tpm2.TPMECCCurve(eccParms.CurveID).Curve()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		eccPoint, err := outPublic.Unique.ECC()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		k.publicKey = &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(eccPoint.X.Buffer),
			Y:     new(big.Int).SetBytes(eccPoint.Y.Buffer),
		}
		k.keyType = TypeECC
		k.curve = c

	case tpm2.TPMAlgSymCipher:
		symParms, err := outPublic.Parameters.SymDetail()
		if err != nil {
			return fmt.Errorf("TPM2_ReadPublic: %w", err)
		}
		if symParms.Sym.Algorithm == tpm2.TPMAlgAES {
			bits, err := symParms.Sym.KeyBits.AES()
			if err != nil {
				return fmt.Errorf("TPM2_ReadPublic: %w", err)
			}
			k.keyType = TypeAES
			k.bits = int(*bits)
		}
	}
	return nil
}

// Marshal returns the serialized version of the key, which can be stored
// offline, and later unmarshaled with [TPM.UnmarshalKey].
func (k *Key) Marshal() ([]byte, error) {
	return k.keyb, nil
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

// Type returns the key type.
func (k *Key) Type() KeyType {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return 0
	}
	return k.keyType
}

// Bits returns the key size.
func (k *Key) Bits() int {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return 0
	}
	return k.bits
}

// Curve returns the key curve ID.
func (k *Key) Curve() elliptic.Curve {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil
	}
	return k.curve
}

// Sign signs a digest with the key (RSA only).
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}

	var hashAlg tpm2.TPMSSchemeHash
	switch h := opts.HashFunc(); h {
	case crypto.SHA1:
		hashAlg = tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA1}
	case crypto.SHA256:
		hashAlg = tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}
	case crypto.SHA384:
		hashAlg = tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA384}
	case crypto.SHA512:
		hashAlg = tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA512}
	default:
		return nil, fmt.Errorf("unexpected hash %v", h)
	}

	switch k.keyType {
	case TypeRSA:
		scheme := tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &hashAlg),
		}
		if _, ok := opts.(*rsa.PSSOptions); ok {
			scheme.Scheme = tpm2.TPMAlgRSAPSS
			scheme.Details = tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSAPSS, &hashAlg)
		}
		resp, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name: tpm2.TPM2BName{
					Buffer: []byte(k.id),
				},
				Auth: tpm2.PasswordAuth(k.t.objectAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: scheme,
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_Sign: %w", err)
		}
		if resp.Signature.SigAlg == tpm2.TPMAlgRSASSA {
			sig, err := resp.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
			return sig.Sig.Buffer, nil
		}
		sig, err := resp.Signature.Signature.RSAPSS()
		if err != nil {
			return nil, err
		}
		return sig.Sig.Buffer, nil

	case TypeECC:
		resp, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name: tpm2.TPM2BName{
					Buffer: []byte(k.id),
				},
				Auth: tpm2.PasswordAuth(k.t.objectAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &hashAlg),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_Sign: %w", err)
		}
		sig, err := resp.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}
		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addASN1IntBytes(b, sig.SignatureR.Buffer)
			addASN1IntBytes(b, sig.SignatureS.Buffer)
		})
		return b.Bytes()

	default:
		return nil, ErrWrongKeyType
	}
}

// Copied from crypto/ecdsa/ecdsa.go
// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/crypto/ecdsa/ecdsa.go;l=347
// Copyright (c) 2009 The Go Authors. All rights reserved.
// https://cs.opensource.google/go/go/+/master:LICENSE
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// Encrypt encrypts cleartext with the key.
func (k *Key) Encrypt(cleartext []byte) (ciphertext []byte, err error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	switch k.keyType {
	case TypeRSA:
		resp, err := tpm2.RSAEncrypt{
			KeyHandle: k.t.loadedHandle,
			Message: tpm2.TPM2BPublicKeyRSA{
				Buffer: cleartext,
			},
			InScheme: tpm2.TPMTRSADecrypt{
				Scheme:  tpm2.TPMAlgOAEP,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_RSAEncrypt: %w", err)
		}
		return resp.OutData.Buffer, nil

	case TypeAES:
		iv := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		resp, err := tpm2.EncryptDecrypt2{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name: tpm2.TPM2BName{
					Buffer: []byte(k.id),
				},
				Auth: tpm2.PasswordAuth(k.t.objectAuth),
			},
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: cleartext,
			},
			Decrypt: false,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_EncryptDecrypt2: %w", err)
		}
		enc := resp.OutData.Buffer
		out := make([]byte, len(iv)+len(enc))
		copy(out, iv)
		copy(out[len(iv):], enc)
		return out, nil

	default:
		return nil, ErrWrongKeyType
	}
}

// Decrypt decrypts ciphertext with the key.
func (k *Key) Decrypt(_ io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	switch k.keyType {
	case TypeRSA:
		resp, err := tpm2.RSADecrypt{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name: tpm2.TPM2BName{
					Buffer: []byte(k.id),
				},
				Auth: tpm2.PasswordAuth(k.t.objectAuth),
			},
			CipherText: tpm2.TPM2BPublicKeyRSA{
				Buffer: ciphertext,
			},
			InScheme: tpm2.TPMTRSADecrypt{
				Scheme:  tpm2.TPMAlgOAEP,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_RSADecrypt: %w", err)
		}
		return resp.Message.Buffer, nil

	case TypeAES:
		if len(ciphertext) < 16 {
			return nil, ErrDecrypt
		}
		resp, err := tpm2.EncryptDecrypt2{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name: tpm2.TPM2BName{
					Buffer: []byte(k.id),
				},
				Auth: tpm2.PasswordAuth(k.t.objectAuth),
			},
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: ciphertext[16:],
			},
			Decrypt: true,
			IV: tpm2.TPM2BIV{
				Buffer: ciphertext[:16],
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_EncryptDecrypt2: %w", err)
		}
		return resp.OutData.Buffer, nil

	default:
		return nil, ErrWrongKeyType
	}
}

func (t *TPM) srk() (tpm2.NamedHandle, func(), error) {
	createPrimaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(t.endorsementAuth),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(t.tpm)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	srk := tpm2.NamedHandle{
		Handle: createPrimaryResp.ObjectHandle,
		Name:   createPrimaryResp.Name,
	}
	return srk, func() {
		tpm2.FlushContext{FlushHandle: srk}.Execute(t.tpm)
	}, nil
}
