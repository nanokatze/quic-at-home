package sec

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

//go:embed cacophony.txt
var testdata []byte

type Vector struct {
	ProtocolName     string   `json:"protocol_name"`
	InitPrologue     string   `json:"init_prologue"`
	InitLocalStatic  string   `json:"init_static"`
	InitRemoteStatic string   `json:"init_remote_static"`
	InitPSKs         []string `json:"init_psks"`
	InitEphemeral    string   `json:"init_ephemeral"`
	RespPrologue     string   `json:"resp_prologue"`
	RespEphemeral    string   `json:"resp_ephemeral"`
	RespLocalStatic  string   `json:"resp_static"`
	RespRemoteStatic string   `json:"resp_remote_static"`
	RespPSKs         []string `json:"resp_psks"`
	HandshakeHash    string   `json:"handshake_hash"`
	Messages         []*struct {
		Payload    string `json:"payload"`
		Ciphertext string `json:"ciphertext"`
	}
}

func TestHandshake(t *testing.T) {
	var cacophony struct {
		Vectors []*Vector `json:"vectors"`
	}
	if err := json.Unmarshal(testdata, &cacophony); err != nil {
		t.Fatal(err)
	}

	v := vectorByName(cacophony.Vectors, "Noise_IK_25519_ChaChaPoly_BLAKE2b")

	alicePrologue, _ := hex.DecodeString(v.InitPrologue)
	aliceLocalStatic, _ := hex.DecodeString(v.InitLocalStatic)
	aliceEphemeral, _ := hex.DecodeString(v.InitEphemeral)
	aliceRemoteStatic, _ := hex.DecodeString(v.InitRemoteStatic)
	alice := NewHandshake(alicePrologue, aliceLocalStatic, aliceRemoteStatic, bytes.NewReader(aliceEphemeral), InitiatorRole)

	bobPrologue, _ := hex.DecodeString(v.RespPrologue)
	bobLocalStatic, _ := hex.DecodeString(v.RespLocalStatic)
	bobEphemeral, _ := hex.DecodeString(v.RespEphemeral)
	bob := NewHandshake(bobPrologue, bobLocalStatic, nil, bytes.NewReader(bobEphemeral), ResponderRole)

	aliceAndBob := []Handshake{alice, bob}

	for i, m := range v.Messages[:2] {
		sender := aliceAndBob[i%2]
		recipient := aliceAndBob[1-i%2]

		wantPayload, _ := hex.DecodeString(m.Payload)
		wantCiphertext, _ := hex.DecodeString(m.Ciphertext)

		ciphertext := bytes.Buffer{}
		if err := sender.WriteMessage(&ciphertext, wantPayload); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if !bytes.Equal(ciphertext.Bytes(), wantCiphertext) {
			t.Fatalf("%d: ciphertext = %x, want %x", i, ciphertext.Bytes(), wantCiphertext)
		}

		payload, err := recipient.ReadMessage(&ciphertext, uint16(len(wantPayload)))
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if !bytes.Equal(payload, wantPayload) {
			t.Fatalf("%d: payload = %x, want %x", i, payload, wantPayload)
		}
	}

	wantHandshakeHash, _ := hex.DecodeString(v.HandshakeHash)

	a1, a2, aliceHandshakeHash := alice.Split()
	if !bytes.Equal(aliceHandshakeHash, wantHandshakeHash) {
		t.Errorf("alice's handshake hash = %x, want %x", aliceHandshakeHash, wantHandshakeHash)
	}

	b1, b2, bobHandshakeHash := bob.Split()
	if !bytes.Equal(bobHandshakeHash, wantHandshakeHash) {
		t.Errorf("bob's handshake hash = %x, want %x", bobHandshakeHash, wantHandshakeHash)
	}

	encrypt := []AEAD{a1, b2}
	decrypt := []AEAD{b1, a2}

	for i, m := range v.Messages[2:] {
		nonce := uint64(i / 2)

		wantPayload, _ := hex.DecodeString(m.Payload)
		wantCiphertext, _ := hex.DecodeString(m.Ciphertext)

		ciphertext := encrypt[i%2].Seal(nil, nonce, wantPayload, nil)
		if !bytes.Equal(ciphertext, wantCiphertext) {
			t.Fatalf("%d: ciphertext = %x, want %x", i, ciphertext, wantCiphertext)
		}

		payload, err := decrypt[i%2].Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if !bytes.Equal(payload, wantPayload) {
			t.Fatalf("%d: payload = %x, want %x", i, payload, wantPayload)
		}
	}
}

func vectorByName(vectors []*Vector, name string) *Vector {
	for _, v := range vectors {
		if v.ProtocolName == name {
			return v
		}
	}
	return nil
}

func BenchmarkHandshake(b *testing.B) {
	r := rand.New(rand.NewSource(42))

	prologue := []byte("C= C= C= C= C=┌(;・ω・)┘")
	alicePrivKey, _ := hex.DecodeString("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
	bobPrivKey, _ := hex.DecodeString("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
	bobPubKey, _ := curve25519.X25519(bobPrivKey, curve25519.Basepoint)

	buf := bytes.Buffer{}
	for i := 0; i < b.N; i++ {
		alice := NewHandshake(prologue, alicePrivKey, bobPubKey, r, InitiatorRole)
		bob := NewHandshake(prologue, bobPrivKey, nil, r, ResponderRole)

		if err := alice.WriteMessage(&buf, nil); err != nil {
			b.Fatal(err)
		}
		if _, err := bob.ReadMessage(&buf, 0); err != nil {
			b.Fatal(err)
		}
		if err := bob.WriteMessage(&buf, nil); err != nil {
			b.Fatal(err)
		}
		if _, err := alice.ReadMessage(&buf, 0); err != nil {
			b.Fatal(err)
		}
	}
}
