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

	"github.com/nogoegst/blake2xb"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
)

var (
	ErrBadSignature = errors.New("bad signature")
)

type ScrambleSignedLocker struct {
	Overhead         int
	MaxPaddingLength int
}

var ScrambleSigned = &ScrambleSignedLocker{
	Overhead:         aeadOverhead + signatureSize,
	MaxPaddingLength: defaultMaxPaddingLength,
}

func (s *ScrambleSignedLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	return ed25519.GenerateKey(r)
}

func ed25519PublicFromPrivate(sk []byte) []byte {
	pk := make([]byte, ed25519.PublicKeySize)
	copy(pk, sk[32:])
	return pk
}

func (s *ScrambleSignedLocker) deriveSymmetricKey(keymaterial, nonce []byte) ([]byte, error) {
	b2xcfg := blake2xb.NewConfig(uint32(chacha20poly1305.KeySize))
	b2xcfg.Salt = nonce
	b2xcfg.Person = []byte("scamblesigned")
	b2x, err := blake2xb.NewWithConfig(b2xcfg)
	if err != nil {
		return nil, err
	}
	_, err = b2x.Write(keymaterial)
	if err != nil {
		return nil, err
	}
	key := make([]byte, chacha20poly1305.KeySize)
	_, err = io.ReadFull(b2x, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *ScrambleSignedLocker) Seal(pt, key []byte) ([]byte, error) {
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
	padlen := PaddingLength(s.MaxPaddingLength, nonce, secretkey)
	paddedpt := Pad(signedpt, padlen)
	ct := c.Seal(nonce, nonce, paddedpt, IntToBinary(s.MaxPaddingLength))
	return ct, nil
}

func (s *ScrambleSignedLocker) Open(ct, key []byte) ([]byte, error) {
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
	padlen := PaddingLength(s.MaxPaddingLength, nonce, secretkey)
	paddedpt, err := c.Open(nil, nonce, ct[chacha20poly1305.NonceSize:], IntToBinary(s.MaxPaddingLength))
	if err != nil {
		return nil, err
	}
	signedpt, err := Unpad(paddedpt, padlen)
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
