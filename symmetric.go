// symmetric.go - easy-to-use secure symmetric locker.
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

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidSize = errors.New("invalid ciphertext size")
)

type SymmetricLocker struct {
	Overhead         int
	MaxPaddingLength int
}

var Symmetric = &SymmetricLocker{
	Overhead:         aeadOverhead,
	MaxPaddingLength: defaultMaxPaddingLength,
}

func (s *SymmetricLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, nil, err
	}
	return key, key, nil
}

func (s *SymmetricLocker) Seal(pt, key []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	padlen, binpadlen := PaddingLength(s.MaxPaddingLength, nonce, key)
	paddedpt := Pad(pt, padlen)
	ct := c.Seal(nonce, nonce, paddedpt, binpadlen)
	return ct, nil
}

func (s *SymmetricLocker) Open(ct, key []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < chacha20poly1305.NonceSize {
		return nil, ErrInvalidSize
	}
	nonce := ct[:chacha20poly1305.NonceSize]
	padlen, binpadlen := PaddingLength(s.MaxPaddingLength, nonce, key)
	paddedpt, err := c.Open(nil, nonce, ct[chacha20poly1305.NonceSize:], binpadlen)
	if err != nil {
		return nil, err
	}
	pt, err := Unpad(paddedpt, padlen)
	if err != nil {
		return nil, err
	}
	return pt, nil
}
