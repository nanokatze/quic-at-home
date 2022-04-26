package sec

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

type initiatorHandshake struct {
	handshake
}

func (hs *initiatorHandshake) es() error {
	s, err := curve25519.X25519(hs.localEphemeralPrivateKey, hs.remoteStaticPublicKey)
	if err == nil {
		hs.mixKey(s)
	}
	return err
}

func (hs *initiatorHandshake) se() error {
	s, err := curve25519.X25519(hs.localStaticPrivateKey, hs.remoteEphemeralPublicKey)
	if err == nil {
		hs.mixKey(s)
	}
	return err
}

func (hs *initiatorHandshake) ReadMessage(r io.Reader, payloadLen uint16) ([]byte, error) {
	// ← e, ee, se

	hs.remoteEphemeralPublicKey = make([]byte, curve25519.PointSize)
	if _, err := io.ReadFull(r, hs.remoteEphemeralPublicKey); err != nil {
		return nil, err
	}
	hs.mixHash(hs.remoteEphemeralPublicKey)
	if err := hs.ee(); err != nil {
		return nil, err
	}
	if err := hs.se(); err != nil {
		return nil, err
	}
	sealedPayload := make([]byte, int(payloadLen)+16)
	if _, err := io.ReadFull(r, sealedPayload); err != nil {
		return nil, err
	}
	return hs.openAndHash(nil, sealedPayload)
}

func (hs *initiatorHandshake) WriteMessage(w io.Writer, payload []byte) error {
	// → e, es, s, ss

	if err := hs.generateLocalEphemeralPrivateKey(); err != nil {
		return err
	}
	localEphemeralPublicKey, err := curve25519.X25519(hs.localEphemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(localEphemeralPublicKey); err != nil {
		return err
	}
	hs.mixHash(localEphemeralPublicKey)
	if err := hs.es(); err != nil {
		return err
	}
	localStaticPublicKey, err := curve25519.X25519(hs.localStaticPrivateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(hs.sealAndHash(nil, localStaticPublicKey)); err != nil {
		return err
	}
	if err := hs.ss(); err != nil {
		return err
	}
	if _, err := w.Write(hs.sealAndHash(nil, payload)); err != nil {
		return err
	}
	return nil
}
