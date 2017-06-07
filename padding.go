package locker

import (
	"encoding/binary"
	"github.com/nogoegst/blake2xb"
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
	b2xc := blake2xb.NewConfig(8)
	b2xc.Key = nonce
	b2x, err := blake2xb.NewWithConfig(b2xc)
	if err != nil {
		panic(err)
	}
	b2x.Write(key)
	d := b2x.Sum(nil)

	r := binary.BigEndian.Uint32(d[:4])
	padlen := r & (max - 1)
	binpadlen := make([]byte, 4)
	binary.BigEndian.PutUint32(binpadlen, padlen)
	return int(padlen), binpadlen
}
