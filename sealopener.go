// sealopener.go - a thing that Seals and Opens.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to locker, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package locker

type Sealer interface {
	Seal(pt, key []byte) ([]byte, error)
}

type Opener interface {
	Open(ct, key []byte) ([]byte, error)
}

type SealOpener interface {
	Sealer
	Opener
}
