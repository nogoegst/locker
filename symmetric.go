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

	"github.com/nogoegst/chacha20poly1305"
	"github.com/nogoegst/padding"
)

var (
	ErrInvalidSize = errors.New("invalid ciphertext size")
)

type symmetricLocker struct {
	Overhead         int
	MaxPaddingLength int
}

var Symmetric = &symmetricLocker{
	Overhead:         aeadOverhead,
	MaxPaddingLength: defaultMaxPaddingLength,
}

func (s *symmetricLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, nil, err
	}
	return key, key, nil
}

func (s *symmetricLocker) Seal(key, pt, adata []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	padlen := padding.Length(s.MaxPaddingLength, nonce, key)
	paddedpt := padding.Pad(pt, padlen)
	ad := append(padding.IntToBinary(s.MaxPaddingLength), adata...)
	ct := c.Seal(nonce, nonce, paddedpt, ad)
	return ct, nil
}

func (s *symmetricLocker) Open(key, ct, adata []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < chacha20poly1305.NonceSize {
		return nil, ErrInvalidSize
	}
	nonce := ct[:chacha20poly1305.NonceSize]
	ad := append(padding.IntToBinary(s.MaxPaddingLength), adata...)
	paddedpt, err := c.Open(nil, nonce, ct[chacha20poly1305.NonceSize:], ad)
	if err != nil {
		return nil, err
	}
	padlen := padding.Length(s.MaxPaddingLength, nonce, key)
	pt, err := padding.Unpad(paddedpt, padlen)
	if err != nil {
		return nil, err
	}
	return pt, nil
}
