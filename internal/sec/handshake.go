package sec

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

type Role int

const (
	InitiatorRole Role = 1
	ResponderRole Role = 2
)

type Handshake interface {
	ReadMessage(r io.Reader, payloadLen uint16) (payload []byte, err error)
	WriteMessage(w io.Writer, payload []byte) error
	Split() (c1 AEAD, c2 AEAD, handshakeHash []byte)
}

func NewHandshake(prologue []byte, localStaticPrivateKey, remoteStaticPublicKey []byte, rand io.Reader, role Role) Handshake {
	hs := handshake{
		symmetric: newSymmetric(),
		rand:      rand,
	}
	hs.mixHash(prologue)
	hs.localStaticPrivateKey = append([]byte(nil), localStaticPrivateKey...)

	switch role {
	case InitiatorRole:
		hs.remoteStaticPublicKey, _ = hs.openAndHash(nil, remoteStaticPublicKey) // can't fail because hs.symmetric.aead is a nilAEAD
		return &initiatorHandshake{hs}

	case ResponderRole:
		localStaticPublicKey, err := curve25519.X25519(localStaticPrivateKey, curve25519.Basepoint)
		if err != nil {
			panic(err)
		}
		hs.sealAndHash(nil, localStaticPublicKey)
		return &responderHandshake{hs}
	}

	panic("bad role")
}
