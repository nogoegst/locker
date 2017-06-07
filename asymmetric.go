// asymmetric.go - easy-to-use secure asymmetric locker.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

import (
	"io"

	"git.schwanenlied.me/yawning/chacha20"
	"golang.org/x/crypto/curve25519"
)

type AsymmetricLocker struct {
	Overhead int
}

var Asymmetric = &AsymmetricLocker{
	Overhead: Symmetric.Overhead,
}

var zeros [chacha20.HNonceSize]byte

func (s *AsymmetricLocker) GenerateKey(r io.Reader) (publicKey, privateKey []byte, err error) {
	var pk, sk [32]byte
	_, err = io.ReadFull(r, sk[:])
	if err != nil {
		return
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	publicKey, privateKey = pk[:], sk[:]
	return
}

func (s *AsymmetricLocker) Precompute(sharedKey, privateKey, publicKey *[32]byte) {
	curve25519.ScalarMult(sharedKey, privateKey, publicKey)
	chacha20.HChaCha(sharedKey[:], &zeros, sharedKey)
}

func (s *AsymmetricLocker) unpackAndDerive(key []byte) ([]byte, error) {
	var sharedKey [32]byte
	var privateKey [32]byte
	var theirPublicKey [32]byte
	copy(privateKey[:], key[:32])
	copy(theirPublicKey[:], key[32:])
	s.Precompute(&sharedKey, &privateKey, &theirPublicKey)
	return sharedKey[:], nil
}

func (s *AsymmetricLocker) Seal(pt, key []byte) ([]byte, error) {
	sharedKey, err := s.unpackAndDerive(key)
	if err != nil {
		return nil, err
	}
	return Symmetric.Seal(pt, sharedKey)
}

func (s *AsymmetricLocker) Open(ct, key []byte) ([]byte, error) {
	sharedKey, err := s.unpackAndDerive(key)
	if err != nil {
		return nil, err
	}
	return Symmetric.Open(ct, sharedKey)
}
