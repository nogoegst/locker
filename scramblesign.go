// scramblesign.go - easy-to-use secure signcrypted locker.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/nogoegst/padding"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
)

var (
	ErrBadSignature = errors.New("bad signature")
)

type scrambleSignedLocker struct {
	Overhead         int
	MaxPaddingLength int
}

var ScrambleSigned = &scrambleSignedLocker{
	Overhead:         aeadOverhead + signatureSize,
	MaxPaddingLength: defaultMaxPaddingLength,
}

func (s *scrambleSignedLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	return ed25519.GenerateKey(r)
}

func ed25519PublicFromPrivate(sk []byte) []byte {
	pk := make([]byte, ed25519.PublicKeySize)
	copy(pk, sk[32:])
	return pk
}

func (s *scrambleSignedLocker) deriveSymmetricKey(keymaterial, nonce []byte) ([]byte, error) {
	h, err := blake2b.New256(nonce)
	if err != nil {
		return nil, err
	}
	h.Write(keymaterial)
	key := h.Sum(nil)
	if len(key) != chacha20poly1305.KeySize {
		panic("chacha20poly1305 keysize is not 256 bits")
	}
	return key, nil
}

func (s *scrambleSignedLocker) Seal(key, pt, adata []byte) ([]byte, error) {
	sig := ed25519.Sign(ed25519.PrivateKey(key), pt)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	pubkey := ed25519PublicFromPrivate(key)
	secretkey, err := s.deriveSymmetricKey(pubkey, nonce)
	if err != nil {
		return nil, err
	}

	c, err := chacha20poly1305.New(secretkey)
	if err != nil {
		return nil, err
	}
	signedpt := append(sig, pt...)
	padlen := padding.Length(s.MaxPaddingLength, nonce, secretkey)
	paddedpt := padding.Pad(signedpt, padlen)
	ad := append(padding.IntToBinary(s.MaxPaddingLength), adata...)
	ct := c.Seal(nonce, nonce, paddedpt, ad)
	return ct, nil
}

func (s *scrambleSignedLocker) Open(key, ct, adata []byte) ([]byte, error) {
	if len(ct) < s.Overhead {
		return nil, ErrInvalidSize
	}
	nonce := ct[:chacha20poly1305.NonceSize]
	secretkey, err := s.deriveSymmetricKey(key, nonce)
	if err != nil {
		return nil, err
	}

	c, err := chacha20poly1305.New(secretkey)
	if err != nil {
		return nil, err
	}
	padlen := padding.Length(s.MaxPaddingLength, nonce, secretkey)
	ad := append(padding.IntToBinary(s.MaxPaddingLength), adata...)
	paddedpt, err := c.Open(nil, nonce, ct[chacha20poly1305.NonceSize:], ad)
	if err != nil {
		return nil, err
	}
	signedpt, err := padding.Unpad(paddedpt, padlen)
	if err != nil {
		return nil, err
	}
	sig := signedpt[:ed25519.SignatureSize]
	pt := signedpt[ed25519.SignatureSize:]
	ok := ed25519.Verify(ed25519.PublicKey(key), pt, sig)
	if !ok {
		return nil, ErrBadSignature
	}
	return pt, nil
}
