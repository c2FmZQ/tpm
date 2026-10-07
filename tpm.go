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
// TPM to create and use RSA, ECC, AES, and HMAC keys that are bound to that TPM.
// The keys can never be used without the TPM that was used to create them.
//
// Any number of keys can be created and used concurrently. The library takes
// care loading the right key in the TPM, as needed.
//
// By default, 2048-bit RSA keys are created. AES keys, ECC keys, HMAC keys, and
// RSA keys of different sizes can also be created if the TPM supports them.
//
// Keys are created under a storage root key (SRK) in the owner hierarchy, so
// clearing the TPM invalidates them. All commands that use keys are protected
// by HMAC sessions salted with the SRK: auth values are never sent to the TPM
// in cleartext, secret parameters are encrypted, and responses are
// authenticated. Serialized keys are bound to the SRK that they were created
// under.
package tpm

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
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
	TypeRSA  KeyType = 1
	TypeECC  KeyType = 2
	TypeAES  KeyType = 3
	TypeHMAC KeyType = 4
)

var (
	ErrWrongKeyType = errors.New("operation not implemented with this key type")
	ErrInvalidCurve = errors.New("invalid curve id")
	ErrDecrypt      = errors.New("decryption error")
	ErrInvalidKey   = errors.New("invalid or unsupported key")
	ErrKeyUsage     = errors.New("operation not permitted by the key's usage")
	ErrWrongTPM     = errors.New("key was created with a different TPM or storage root key")
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
	case TypeHMAC:
		return "HMAC"
	default:
		return ""
	}
}

// Option is an option that can be passed to New.
type Option func(*TPM)

// WithTPM specifies an already open TPM device to use. The TPM may be shared
// with other users, so New leaves existing objects alone.
func WithTPM(rwc io.ReadWriteCloser) Option {
	return func(t *TPM) {
		t.tpm = transport.FromReadWriteCloser(rwc)
	}
}

// WithOwnerAuth specifies the owner (storage hierarchy) passphrase. Keys are
// created under a primary key in the owner hierarchy, so clearing the TPM
// (TPM2_Clear) invalidates them.
func WithOwnerAuth(pp []byte) Option {
	return func(t *TPM) {
		t.ownerAuth = slices.Clone(pp)
	}
}

// WithObjectAuth specifies the passphrase to set on created keys.
func WithObjectAuth(pp []byte) Option {
	return func(t *TPM) {
		t.objectAuth = slices.Clone(pp)
	}
}

// New returns a new TPM that's ready to use.
//
// Without [WithTPM], New opens /dev/tpmrm0, or /dev/tpm0 if the kernel
// resource manager isn't available.
func New(opts ...Option) (*TPM, error) {
	var tpm TPM
	for _, o := range opts {
		o(&tpm)
	}
	if tpm.tpm == nil {
		t, err := linuxtpm.Open("/dev/tpmrm0")
		if errors.Is(err, os.ErrNotExist) {
			if t, err = linuxtpm.Open("/dev/tpm0"); err != nil {
				return nil, err
			}
			// Without the resource manager, transient objects
			// left behind by a previous process stay loaded.
			// /dev/tpm0 can only be opened by one process at a
			// time, so they can't belong to anyone else.
			if err := flushTransientHandles(t); err != nil {
				t.Close()
				return nil, err
			}
		}
		if err != nil {
			return nil, err
		}
		tpm.tpm = t
	}
	return &tpm, nil
}

func flushTransientHandles(t transport.TPM) error {
	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 100,
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("TPM2_GetCapability: %w", err)
	}
	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("TPM2_GetCapability(Handles): %w", err)
	}
	for _, h := range handles.Handle {
		tpm2.FlushContext{FlushHandle: h}.Execute(t)
	}
	return nil
}

var _ io.Closer = (*TPM)(nil)

// TPM uses a local Trusted Platform Module (TPM) device to create and use
// cryptographic keys that are bound to that TPM. The keys can never be used
// without the TPM created them.
type TPM struct {
	mu           sync.Mutex
	tpm          transport.TPMCloser
	objectAuth   []byte
	ownerAuth    []byte
	loadedKey    string
	loadedHandle tpm2.TPMHandle
	srk          tpm2.NamedHandle
	srkPublic    tpm2.TPMTPublic
}

type keyOptions struct {
	keyType KeyType
	bits    int
	curve   elliptic.Curve
	usage   keyUsage
}

type keyUsage int

const (
	usageAny keyUsage = iota
	usageSign
	usageDecrypt
)

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

// WithSigningOnly restricts a new RSA or ECC key to signing. The key can't be
// used to decrypt.
//
// By default, RSA and ECC keys can be used for both signing and decryption.
// The TPM requires such dual-use keys to have no fixed scheme, so they can
// also be used with other schemes than the ones that this package uses (e.g.
// raw RSA decryption), by anyone who can use the key directly with the TPM.
func WithSigningOnly() KeyOption {
	return func(opts *keyOptions) {
		opts.usage = usageSign
	}
}

// WithDecryptionOnly restricts a new RSA key to RSA-OAEP decryption with
// SHA-256. The key can't be used to sign.
//
// See [WithSigningOnly].
func WithDecryptionOnly() KeyOption {
	return func(opts *keyOptions) {
		opts.usage = usageDecrypt
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

// WithHMAC indicates that an HMAC key should be created.
func WithHMAC(bits int) KeyOption {
	return func(opts *keyOptions) {
		opts.keyType = TypeHMAC
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
	switch {
	case opt.usage == usageAny:
	case opt.keyType == TypeRSA:
	case opt.keyType == TypeECC && opt.usage == usageSign:
	default:
		return nil, fmt.Errorf("key usage not supported with %s keys", opt.keyType)
	}
	t.flushLocked()

	srk, err := t.srkLocked()
	if err != nil {
		return nil, err
	}

	var public tpm2.TPMTPublic

	switch opt.keyType {
	case TypeRSA:
		rsaScheme := tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull}
		if opt.usage == usageDecrypt {
			rsaScheme = tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgOAEP,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgOAEP,
					&tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256},
				),
			}
		}
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
				Decrypt:              opt.usage != usageSign,
				SignEncrypt:          opt.usage != usageDecrypt,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme:  rsaScheme,
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
		uniqueSize := opt.curve.Params().BitSize / 8
		unique := make([]byte, 2*uniqueSize)
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
				Decrypt:              opt.usage != usageSign,
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
					X: tpm2.TPM2BECCParameter{Buffer: unique[:uniqueSize]},
					Y: tpm2.TPM2BECCParameter{Buffer: unique[uniqueSize:]},
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

	case TypeHMAC:
		var hashAlg tpm2.TPMAlgID
		switch opt.bits {
		case 384:
			hashAlg = tpm2.TPMAlgSHA384
		case 512:
			hashAlg = tpm2.TPMAlgSHA512
		case 0, 256:
			hashAlg = tpm2.TPMAlgSHA256
		default:
			return nil, fmt.Errorf("HMAC key size %d not supported", opt.bits)
		}

		unique := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, unique); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		public = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: hashAlg,
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
				Decrypt:              false,
				SignEncrypt:          true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(
							tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: hashAlg,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPM2BDigest{Buffer: unique},
			),
		}

	default:
		return nil, ErrWrongKeyType
	}

	createResp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.Handle,
			Name:   srk.Name,
			Auth:   t.sessionLocked(nil, tpm2.AESEncryption(128, tpm2.EncryptIn)),
		},
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
	buf.AddUint8(keyFormatVersion)
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(srk.Name.Buffer)
	})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(priv)
	})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(pub)
	})
	return buf.Bytes()
}

// Serialized key format:
//
//	version (1) || uint16-prefixed SRK name || uint16-prefixed TPM2B_PRIVATE ||
//	uint16-prefixed TPM2B_PUBLIC
//
// The SRK name pins the key to the storage root key that it was created
// under. When the key is loaded, the TPM's SRK must have the same name, and
// all commands are protected by sessions salted with that SRK. A different
// device pretending to be the TPM cannot complete these sessions.
const keyFormatVersion = 1

// Close closes the connections to the TPM.
func (t *TPM) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushLocked()
	if t.srk.Handle != 0 {
		tpm2.FlushContext{FlushHandle: t.srk.Handle}.Execute(t.tpm)
		t.srk = tpm2.NamedHandle{}
	}
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
	var version uint8
	var srkName, savedPriv, savedPub cryptobyte.String
	if !str.ReadUint8(&version) || version != keyFormatVersion ||
		!str.ReadUint16LengthPrefixed(&srkName) ||
		!str.ReadUint16LengthPrefixed(&savedPriv) ||
		!str.ReadUint16LengthPrefixed(&savedPub) ||
		!str.Empty() {
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
	pubContents, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unmarshal: %w", err)
	}
	name, err := tpm2.ObjectName(pubContents)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unmarshal: %w", err)
	}

	srk, err := t.srkLocked()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(srk.Name.Buffer, srkName) {
		return nil, ErrWrongTPM
	}

	out := &Key{
		t:    t,
		id:   hex.EncodeToString(hashed[:]),
		name: *name,
		priv: *priv,
		pub:  *pub,
		keyb: in,
	}
	if err := out.parsePublic(pubContents); err != nil {
		return nil, err
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
	t          *TPM
	id         string
	name       tpm2.TPM2BName
	priv       tpm2.TPM2BPrivate
	pub        tpm2.TPM2BPublic
	keyb       []byte
	keyType    KeyType
	bits       int
	curve      elliptic.Curve
	publicKey  crypto.PublicKey
	canSign    bool
	canDecrypt bool
}

func (k *Key) loadLocked() error {
	if k.t.loadedKey == k.id {
		return nil
	}
	k.t.flushLocked()

	srk, err := k.t.srkLocked()
	if err != nil {
		return err
	}

	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.Handle,
			Name:   srk.Name,
			Auth:   k.t.sessionLocked(nil),
		},
		InPrivate: k.priv,
		InPublic:  k.pub,
	}.Execute(k.t.tpm)
	if err != nil {
		return fmt.Errorf("TPM2_Load: %w", err)
	}
	if !bytes.Equal(loadResp.Name.Buffer, k.name.Buffer) {
		tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(k.t.tpm)
		return errors.New("TPM2_Load: unexpected object name")
	}

	k.t.loadedKey = k.id
	k.t.loadedHandle = loadResp.ObjectHandle
	return nil
}

// parsePublic extracts the key's parameters from its public area.
func (k *Key) parsePublic(outPublic *tpm2.TPMTPublic) error {
	// Only accept keys that were generated inside this TPM and that can't
	// leave it. Anyone with access to the TPM can create or import keys
	// under the SRK, including keys with sensitive data that they know.
	attrs := outPublic.ObjectAttributes
	if !attrs.FixedTPM || !attrs.FixedParent || !attrs.SensitiveDataOrigin || !attrs.UserWithAuth {
		return ErrInvalidKey
	}
	k.canSign = attrs.SignEncrypt
	k.canDecrypt = attrs.Decrypt
	switch tpm2.TPMAlgID(outPublic.Type) {
	case tpm2.TPMAlgRSA:
		rsaParms, err := outPublic.Parameters.RSADetail()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		rsaPubKeyN, err := outPublic.Unique.RSA()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		rsaPubKey, err := tpm2.RSAPub(rsaParms, rsaPubKeyN)
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		k.publicKey = rsaPubKey
		k.keyType = TypeRSA
		k.bits = int(rsaParms.KeyBits)

	case tpm2.TPMAlgECC:
		eccParms, err := outPublic.Parameters.ECCDetail()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		c, err := tpm2.TPMECCCurve(eccParms.CurveID).Curve()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		eccPoint, err := outPublic.Unique.ECC()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
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
			return fmt.Errorf("parsePublic: %w", err)
		}
		if symParms.Sym.Algorithm == tpm2.TPMAlgAES {
			bits, err := symParms.Sym.KeyBits.AES()
			if err != nil {
				return fmt.Errorf("parsePublic: %w", err)
			}
			k.keyType = TypeAES
			k.bits = int(*bits)
		}

	case tpm2.TPMAlgKeyedHash:
		keyedHashParms, err := outPublic.Parameters.KeyedHashDetail()
		if err != nil {
			return fmt.Errorf("parsePublic: %w", err)
		}
		if keyedHashParms.Scheme.Scheme == tpm2.TPMAlgHMAC {
			k.keyType = TypeHMAC
			details, err := keyedHashParms.Scheme.Details.HMAC()
			if err != nil {
				return fmt.Errorf("parsePublic: %w", err)
			}
			switch details.HashAlg {
			case tpm2.TPMAlgSHA384:
				k.bits = 384
			case tpm2.TPMAlgSHA512:
				k.bits = 512
			case tpm2.TPMAlgSHA256:
				k.bits = 256
			default:
				k.bits = -1
			}
		}
	}
	if k.keyType == 0 {
		return ErrInvalidKey
	}
	return nil
}

// Marshal returns the serialized version of the key, which can be stored
// offline, and later unmarshaled with [TPM.UnmarshalKey].
func (k *Key) Marshal() ([]byte, error) {
	return slices.Clone(k.keyb), nil
}

// Public returns the public key.
func (k *Key) Public() crypto.PublicKey {
	return k.publicKey
}

// Type returns the key type.
func (k *Key) Type() KeyType {
	return k.keyType
}

// Bits returns the key size.
func (k *Key) Bits() int {
	return k.bits
}

// Curve returns the key curve ID.
func (k *Key) Curve() elliptic.Curve {
	return k.curve
}

// HMAC returns the HMAC signature of the message.
func (k *Key) HMAC(message []byte) ([]byte, error) {
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	if k.keyType != TypeHMAC {
		return nil, ErrWrongKeyType
	}
	return k.hmacLocked(message)
}

func (k *Key) hmacLocked(message []byte) ([]byte, error) {
	var hashAlg tpm2.TPMAlgID
	switch k.bits {
	case 384:
		hashAlg = tpm2.TPMAlgSHA384
	case 512:
		hashAlg = tpm2.TPMAlgSHA512
	case 256:
		hashAlg = tpm2.TPMAlgSHA256
	default:
		return nil, ErrWrongKeyType
	}

	resp, err := tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: k.t.loadedHandle,
			Name:   k.name,
			Auth:   k.t.sessionLocked(k.t.objectAuth, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
		},
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: message,
		},
		HashAlg: hashAlg,
	}.Execute(k.t.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_HMAC: %w", err)
	}
	return resp.OutHMAC.Buffer, nil
}

// Sign signs a digest with the key (RSA and ECC) or computes the HMAC
// (HMAC keys). The digest must be a SHA-256, SHA-384, or SHA-512 hash.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if !k.canSign {
		return nil, ErrKeyUsage
	}
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}

	h := opts.HashFunc()
	if h == crypto.SHA1 {
		return nil, fmt.Errorf("unexpected hash %v", h)
	}
	tpmHash, err := tpmHashAlg(h)
	if err != nil {
		return nil, err
	}
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("digest length %d, want %d for %v", len(digest), h.Size(), h)
	}
	hashAlg := tpm2.TPMSSchemeHash{HashAlg: tpmHash}

	switch k.keyType {
	case TypeRSA:
		scheme := tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &hashAlg),
		}
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			if pss.SaltLength != 32 {
				return nil, fmt.Errorf("unexpected pss salt length %d, want 32", pss.SaltLength)
			}
			scheme.Scheme = tpm2.TPMAlgRSAPSS
			scheme.Details = tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSAPSS, &hashAlg)
		}
		resp, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name:   k.name,
				Auth:   k.t.sessionLocked(k.t.objectAuth, tpm2.AESEncryption(128, tpm2.EncryptIn)),
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
				Name:   k.name,
				Auth:   k.t.sessionLocked(k.t.objectAuth, tpm2.AESEncryption(128, tpm2.EncryptIn)),
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

	case TypeHMAC:
		return k.hmacLocked(digest)

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
//
// With RSA keys, the cleartext is encrypted with RSA-OAEP (SHA-256) and its
// size is limited by the key size.
//
// With AES keys, the cleartext is encrypted with authenticated encryption
// (AES-GCM) using a single-use data key that is wrapped by the TPM key. There
// is no practical size limit.
func (k *Key) Encrypt(cleartext []byte) (ciphertext []byte, err error) {
	if k.keyType == TypeRSA && !k.canDecrypt {
		return nil, ErrKeyUsage
	}
	switch k.keyType {
	case TypeRSA:
		// Only the public key is needed. Encrypting in software keeps
		// the cleartext off the bus.
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, k.publicKey.(*rsa.PublicKey), cleartext, nil)

	case TypeAES:
		k.t.mu.Lock()
		defer k.t.mu.Unlock()
		if err := k.loadLocked(); err != nil {
			return nil, err
		}
		return k.aesEncryptLocked(cleartext)

	default:
		return nil, ErrWrongKeyType
	}
}

// Decrypt decrypts ciphertext with the key.
//
// With RSA keys, only RSA-OAEP is supported. opts may be nil (SHA-256, no
// label) or a [*rsa.OAEPOptions]. The TPM requires OAEP labels to be
// null-terminated, so a non-empty Label must end with a 0x00 byte.
func (k *Key) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if k.keyType == TypeRSA && !k.canDecrypt {
		return nil, ErrKeyUsage
	}
	k.t.mu.Lock()
	defer k.t.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, err
	}
	switch k.keyType {
	case TypeRSA:
		hashAlg, label, err := oaepParams(opts)
		if err != nil {
			return nil, err
		}
		resp, err := tpm2.RSADecrypt{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.t.loadedHandle,
				Name:   k.name,
				Auth:   k.t.sessionLocked(k.t.objectAuth, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
			},
			CipherText: tpm2.TPM2BPublicKeyRSA{
				Buffer: ciphertext,
			},
			InScheme: tpm2.TPMTRSADecrypt{
				Scheme:  tpm2.TPMAlgOAEP,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{HashAlg: hashAlg}),
			},
			Label: tpm2.TPM2BData{
				Buffer: label,
			},
		}.Execute(k.t.tpm)
		if err != nil {
			return nil, fmt.Errorf("TPM2_RSADecrypt: %w", err)
		}
		return resp.Message.Buffer, nil

	case TypeAES:
		return k.aesDecryptLocked(ciphertext)

	default:
		return nil, ErrWrongKeyType
	}
}

// oaepParams returns the TPM hash algorithm and label to use for RSA-OAEP
// decryption with the given options.
func oaepParams(opts crypto.DecrypterOpts) (tpm2.TPMIAlgHash, []byte, error) {
	if opts == nil {
		return tpm2.TPMAlgSHA256, nil, nil
	}
	o, ok := opts.(*rsa.OAEPOptions)
	if !ok {
		return 0, nil, fmt.Errorf("unsupported decrypter options %T", opts)
	}
	if o.MGFHash != 0 && o.MGFHash != o.Hash {
		return 0, nil, errors.New("OAEP MGF hash must be the same as the label hash")
	}
	hashAlg, err := tpmHashAlg(o.Hash)
	if err != nil {
		return 0, nil, err
	}
	if len(o.Label) > 0 && o.Label[len(o.Label)-1] != 0 {
		return 0, nil, errors.New("OAEP label must be null-terminated")
	}
	return hashAlg, o.Label, nil
}

func tpmHashAlg(h crypto.Hash) (tpm2.TPMIAlgHash, error) {
	switch h {
	case crypto.SHA1:
		return tpm2.TPMAlgSHA1, nil
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("unexpected hash %v", h)
	}
}

// AES ciphertext format:
//
//	version (1) || iv (16) || wrapped data key (32) || AES-GCM ciphertext+tag
//
// A random data key is generated for each message and wrapped (AES-CFB) by the
// TPM key. The message itself is sealed with AES-GCM in software, using a key
// derived from the data key. The data key is never reused, so a fixed nonce is
// safe. The header is authenticated as additional data.
const (
	aesVersion    = 1
	aesIVSize     = 16
	aesDataKeyLen = 32
	aesHeaderSize = 1 + aesIVSize + aesDataKeyLen
)

func (k *Key) aesEncryptLocked(cleartext []byte) ([]byte, error) {
	header := make([]byte, aesHeaderSize)
	header[0] = aesVersion
	iv := header[1 : 1+aesIVSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	dataKey := make([]byte, aesDataKeyLen)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	wrapped, err := k.tpmAESLocked(dataKey, iv, false)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != aesDataKeyLen {
		return nil, errors.New("TPM2_EncryptDecrypt2: unexpected output size")
	}
	copy(header[1+aesIVSize:], wrapped)

	aead, err := newDataKeyAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(header, nonce, cleartext, header), nil
}

func (k *Key) aesDecryptLocked(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aesHeaderSize || ciphertext[0] != aesVersion {
		return nil, ErrDecrypt
	}
	header := ciphertext[:aesHeaderSize]
	iv := header[1 : 1+aesIVSize]
	dataKey, err := k.tpmAESLocked(header[1+aesIVSize:], iv, true)
	if err != nil {
		return nil, err
	}
	aead, err := newDataKeyAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	out, err := aead.Open(nil, nonce, ciphertext[aesHeaderSize:], header)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

func newDataKeyAEAD(dataKey []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, dataKey, nil, "github.com/c2FmZQ/tpm AES-GCM", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (k *Key) tpmAESLocked(in, iv []byte, decrypt bool) ([]byte, error) {
	resp, err := tpm2.EncryptDecrypt2{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.t.loadedHandle,
			Name:   k.name,
			Auth:   k.t.sessionLocked(k.t.objectAuth, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
		},
		Message: tpm2.TPM2BMaxBuffer{
			Buffer: in,
		},
		Decrypt: decrypt,
		IV: tpm2.TPM2BIV{
			Buffer: iv,
		},
	}.Execute(k.t.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_EncryptDecrypt2: %w", err)
	}
	return resp.OutData.Buffer, nil
}

// srkLocked returns the storage root key (SRK), creating it if needed. The SRK
// is the parent of all the keys, and it is used to salt the sessions that
// protect the commands sent to the TPM. It stays loaded until Close.
func (t *TPM) srkLocked() (tpm2.NamedHandle, error) {
	if t.srk.Handle != 0 {
		return t.srk, nil
	}
	createPrimaryResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			// No salt is available yet. The HMAC session keeps
			// the owner auth value off the bus.
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(t.ownerAuth)),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(t.tpm)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	flush := func() {
		tpm2.FlushContext{FlushHandle: createPrimaryResp.ObjectHandle}.Execute(t.tpm)
	}
	pub, err := createPrimaryResp.OutPublic.Contents()
	if err != nil {
		flush()
		return tpm2.NamedHandle{}, fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		flush()
		return tpm2.NamedHandle{}, fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	if !bytes.Equal(name.Buffer, createPrimaryResp.Name.Buffer) {
		flush()
		return tpm2.NamedHandle{}, errors.New("TPM2_CreatePrimary: unexpected object name")
	}
	t.srk = tpm2.NamedHandle{
		Handle: createPrimaryResp.ObjectHandle,
		Name:   *name,
	}
	t.srkPublic = *pub
	return t.srk, nil
}

// sessionLocked returns a one-time HMAC session, salted with the SRK, to
// authorize the use of an object with the given auth value. The auth value is
// never sent to the TPM, the TPM's response is authenticated, and opts can
// enable encryption of the first command and/or response parameter. The SRK
// must already be loaded.
func (t *TPM) sessionLocked(auth []byte, opts ...tpm2.AuthOption) tpm2.Session {
	opts = append([]tpm2.AuthOption{
		tpm2.Auth(auth),
		tpm2.Salted(t.srk.Handle, t.srkPublic),
	}, opts...)
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)
}
