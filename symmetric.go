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

const (
	KeySize                  = chacha20poly1305.KeySize
	chacha20poly1305Overhead = 16
	MACOverhead              = chacha20poly1305Overhead
	Overhead                 = chacha20poly1305.NonceSize + MACOverhead
)

var (
	ErrInvalidSize = errors.New("invalid ciphertext size")
)

type SymmetricLocker struct {
	KeySize int
}

func NewSymmetric() *SymmetricLocker {
	l := &SymmetricLocker{
		KeySize: KeySize,
	}
	return l
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
	ct := c.Seal(nonce, nonce, pt, nil)
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
	pt, err := c.Open(nil, ct[:chacha20poly1305.NonceSize], ct[chacha20poly1305.NonceSize:], nil)
	return pt, err
}
