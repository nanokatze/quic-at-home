package quic

import (
	"time"

	"golang.org/x/crypto/curve25519"
)

const timerGranularity = 5 * time.Millisecond

// !!!noisePrologue, maxPacketSize and maxAckDelay of peers must equal for them to establish connection!!!

// noisePrologue is the prologue string for use during Noise handshake (see
// Prologue section of Noise).
var noisePrologue = []byte("My Noise Prologue")

// maxPacketSize puts an upper bound on size of packets received and sent over
// the underlying quic (UDP) and is the required size of an initial packet.
const maxPacketSize = 1280

// Delay before sending an ACK in response to a packet.
const maxAckDelay = 40 * time.Millisecond

type PublicKey []byte

type PrivateKey []byte

func (privKey PrivateKey) Public() PublicKey {
	publicKey, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	return publicKey
}

// Config is used to configure a Mux. A config must not be modified once while
// in use. A Config may be in use by multiple Muxes simultaneously.
type Config struct {
	// StreamReceiveWindow specifies size of the receive window to use for
	// receiving the reliable stream data. StreamReceiveWindow must be
	// non-zero.
	StreamReceiveWindow int

	// MaxStreamBytesInFlight bounds how many bytes carrying reliable stream
	// data can be in flight.
	MaxStreamBytesInFlight int

	// PrivateKey contains the static private key. The public counterpart is
	// presented to the remote party during the handshake. The remote party
	// may discriminate and deny peers based on their public keys.
	PrivateKey PrivateKey

	// Listen for incoming connections.
	Listen bool
}
