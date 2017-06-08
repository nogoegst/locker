// noop.go - empty locker.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

import (
	"errors"
	"io"
)

type noopLocker struct {
}

var Noop = &noopLocker{}

func (s *noopLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	return nil, nil, errors.New("pointless operation")
}

func (s *noopLocker) Seal(pt, key []byte) ([]byte, error) {
	return pt, nil
}

func (s *noopLocker) Open(ct, key []byte) ([]byte, error) {
	return ct, nil
}
