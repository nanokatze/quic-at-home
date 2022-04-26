package sec

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// See The SymmetricState object section of Noise.
type symmetric struct {
	aead        AEAD
	nonce       uint64
	chainingKey []byte
	hash        []byte
}

func newSymmetric() symmetric {
	s := symmetric{aead: nilAEAD{}}
	s.hash = []byte("Noise_IK_25519_ChaChaPoly_BLAKE2b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	s.chainingKey = append([]byte(nil), s.hash...)
	return s
}

func (s *symmetric) mixHash(data []byte) {
	hash, _ := blake2b.New512(nil)
	hash.Write(s.hash)
	hash.Write(data)
	s.hash = hash.Sum(nil)
}

func (s *symmetric) mixKey(inputKeyMaterial []byte) {
	mac := hmac.New(func() hash.Hash {
		hash, _ := blake2b.New512(nil)
		return hash
	}, s.chainingKey)
	mac.Write(inputKeyMaterial)
	tempKey := mac.Sum(nil)
	mac2 := hmac.New(func() hash.Hash {
		hash, _ := blake2b.New512(nil)
		return hash
	}, tempKey)
	mac2.Write([]byte{0x01})
	output1 := mac2.Sum(nil)
	mac2.Reset()
	mac2.Write(output1)
	mac2.Write([]byte{0x02})
	output2 := mac2.Sum(nil)
	s.aead = newChaCha20Poly1305AEAD(output2[:32])
	s.nonce = 0
	s.chainingKey = output1
}

func (s *symmetric) Split() (AEAD, AEAD, []byte) {
	mac := hmac.New(func() hash.Hash {
		hash, _ := blake2b.New512(nil)
		return hash
	}, s.chainingKey)
	tempKey := mac.Sum(nil)
	mac2 := hmac.New(func() hash.Hash {
		hash, _ := blake2b.New512(nil)
		return hash
	}, tempKey)
	mac2.Write([]byte{0x01})
	output1 := mac2.Sum(nil)
	mac2.Reset()
	mac2.Write(output1)
	mac2.Write([]byte{0x02})
	output2 := mac2.Sum(nil)
	return newChaCha20Poly1305AEAD(output1[:32]), newChaCha20Poly1305AEAD(output2[:32]), append([]byte(nil), s.hash...)
}

func (s *symmetric) sealAndHash(dst, plaintext []byte) []byte {
	ciphertext := s.aead.Seal(dst, s.nonce, plaintext, s.hash)
	s.mixHash(ciphertext)
	s.nonce++
	return ciphertext
}

func (s *symmetric) openAndHash(dst, ciphertext []byte) ([]byte, error) {
	plaintext, err := s.aead.Open(dst, s.nonce, ciphertext, s.hash)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	s.nonce++
	return plaintext, nil
}
