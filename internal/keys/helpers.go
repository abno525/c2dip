package keys

import (
	"bytes"

	"golang.org/x/crypto/curve25519"
)

func bytesReader(raw []byte) *bytes.Reader { return bytes.NewReader(raw) }

func x25519(private []byte) ([]byte, error) {
	return curve25519.X25519(private, curve25519.Basepoint)
}
