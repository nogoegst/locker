// padding.go - simple random padding.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/blake2b"
)

// PaddingLength calculates length of padding for given nonce and key
// in range [0:maxlen). maxlen must be a power of two and maxlen < 2^32-1.
func PaddingLength(maxlen int, nonce, key []byte) (int, []byte) {
	max := uint32(maxlen)
	if max != (max << 1 >> 1) {
		panic("max is out of range")
	}
	if max&(max-1) != 0 {
		panic("max padding length is not power of two")
	}
	h, err := blake2b.New256(key)
	if err != nil {
		panic(err)
	}
	h.Write(nonce)
	d := h.Sum(nil)

	r := binary.BigEndian.Uint32(d[:4])
	padlen := r & (max - 1)
	binpadlen := make([]byte, 4)
	binary.BigEndian.PutUint32(binpadlen, padlen)
	return int(padlen), binpadlen
}

// Pad prepends padlen zero bytes to pt.
func Pad(pt []byte, padlen int) []byte {
	paddedpt := make([]byte, padlen+len(pt))
	subtle.ConstantTimeCopy(1, paddedpt[padlen:], pt)
	return paddedpt
}

// Uppad removes first padlen bytes of paddedpt.
func Unpad(paddedpt []byte, padlen int) ([]byte, error) {
	if subtle.ConstantTimeLessOrEq(padlen, len(paddedpt)) == 0 {
		return nil, errors.New("plaintext is shorter than padding")
	}
	pt := paddedpt[padlen:]
	return pt, nil
}
