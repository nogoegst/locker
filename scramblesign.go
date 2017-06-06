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
}

func NewScrambleSigned() *ScrambleSignedLocker {
	return &ScrambleSignedLocker{}
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
	b2xcfg := blake2xb.NewXConfig(uint32(chacha20poly1305.KeySize))
	b2xcfg.Salt = nonce
	b2xcfg.Person = []byte("scamblesigned")
	b2x, err := blake2xb.NewX(b2xcfg)
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
	ct := c.Seal(nonce, nonce, append(sig, pt...), nil)
	return ct, nil
}

func (s *ScrambleSignedLocker) Open(ct, key []byte) ([]byte, error) {
	if len(ct) < chacha20poly1305.NonceSize+ed25519.SignatureSize+chacha20poly1305Overhead {
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
	pt, err := c.Open(nil, nonce, ct[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, err
	}
	ok := ed25519.Verify(ed25519.PublicKey(key), pt[64:], pt[:64])
	if !ok {
		return nil, ErrBadSignature
	}
	return pt[64:], nil
}
