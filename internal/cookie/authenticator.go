package cookie

import (
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Authenticator struct {
	rand io.Reader
	aead cipher.AEAD
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(rand io.Reader) (*Authenticator, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err) // unreachable
	}
	return &Authenticator{
		rand: rand,
		aead: aead,
	}, nil
}

// Sign generates a cookie for additionalData, to be verified with
// Verify. Sign fails iff Read from rand fails.
func (a *Authenticator) Sign(dst, additionalData []byte) ([]byte, error) {
	dst = sliceForAppendHead(dst, a.aead.NonceSize()+a.aead.Overhead())
	nonce, tag := dst[:a.aead.NonceSize()], dst[a.aead.NonceSize():]
	if _, err := io.ReadFull(a.rand, nonce); err != nil {
		return nil, err
	}
	return append(nonce, a.aead.Seal(tag[:0], nonce, nil, additionalData)...), nil
}

func (a *Authenticator) MustSign(dst, additionalData []byte) []byte {
	cookie, err := a.Sign(dst, additionalData)
	if err != nil {
		panic(err)
	}
	return cookie
}

// Verify probabilistically tests if the cookie was generated by this
// authenticator for given additionalData.
func (a *Authenticator) Verify(cookie, additionalData []byte) bool {
	if len(cookie) != a.aead.NonceSize()+a.aead.Overhead() {
		return false
	}
	nonce, tag := cookie[:a.aead.NonceSize()], cookie[a.aead.NonceSize():]
	if _, err := a.aead.Open(nil, nonce, tag, additionalData); err != nil {
		return false
	}
	return true
}

// sliceForAppendHead is like sliceForAppend, but only returns the head and does
// not perform copy.
func sliceForAppendHead(in []byte, n int) []byte {
	if n > cap(in) {
		in = make([]byte, n)
	}
	return in[:n]
}
