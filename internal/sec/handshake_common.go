package sec

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

type handshake struct {
	symmetric

	rand io.Reader

	localEphemeralPrivateKey []byte
	localStaticPrivateKey    []byte
	remoteEphemeralPublicKey []byte
	remoteStaticPublicKey    []byte
}

func (hs *handshake) generateLocalEphemeralPrivateKey() error {
	hs.localEphemeralPrivateKey = make([]byte, curve25519.ScalarSize)
	_, err := io.ReadFull(hs.rand, hs.localEphemeralPrivateKey)
	return err
}

func (hs *handshake) ee() error {
	x, err := curve25519.X25519(hs.localEphemeralPrivateKey, hs.remoteEphemeralPublicKey)
	if err == nil {
		hs.mixKey(x)
	}
	return err
}

func (hs *handshake) ss() error {
	x, err := curve25519.X25519(hs.localStaticPrivateKey, hs.remoteStaticPublicKey)
	if err == nil {
		hs.mixKey(x)
	}
	return err
}
