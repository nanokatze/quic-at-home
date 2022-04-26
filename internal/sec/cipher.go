package sec

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// See The CipherState object section of Noise. This implementation delegates
// nonce concerns to the user.
type AEAD interface {
	Seal(dst []byte, nonce uint64, plaintext, additionalData []byte) []byte
	Open(dst []byte, nonce uint64, ciphertext, additionalData []byte) ([]byte, error)
}

// See The ChaChaPoly cipher functions section of Noise.
type chacha20poly1305AEAD struct {
	nonceBuf []byte
	aead     cipher.AEAD
}

func newChaCha20Poly1305AEAD(key []byte) AEAD {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	return &chacha20poly1305AEAD{
		nonceBuf: make([]byte, 12),
		aead:     aead,
	}
}

func (c *chacha20poly1305AEAD) Seal(dst []byte, nonce uint64, plaintext, additionalData []byte) []byte {
	binary.LittleEndian.PutUint64(c.nonceBuf[4:], nonce)
	return c.aead.Seal(dst, c.nonceBuf, plaintext, additionalData)
}

func (c *chacha20poly1305AEAD) Open(dst []byte, nonce uint64, ciphertext, additionalData []byte) ([]byte, error) {
	binary.LittleEndian.PutUint64(c.nonceBuf[4:], nonce)
	return c.aead.Open(dst, c.nonceBuf, ciphertext, additionalData)
}

type nilAEAD struct{}

func (nilAEAD) Seal(dst []byte, nonce uint64, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}

func (nilAEAD) Open(dst []byte, nonce uint64, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}
