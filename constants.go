// constants.go - locker-wide constants.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

import (
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/poly1305"
)

const (
	aeadOverhead  = chacha20poly1305.NonceSize + poly1305.TagSize
	signatureSize = ed25519.SignatureSize
)
