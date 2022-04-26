package quic

import (
	"bytes"
	"net/netip"
	"sync"

	"github.com/nanokatze/quic-at-home/internal/sec"
	"github.com/nanokatze/quic-at-home/internal/wire"
)

type handshaker struct {
	mux *Mux
	id  wire.ConnID

	once     sync.Once
	closed   chan struct{}
	closeErr error

	in chan []byte

	raddr netip.AddrPort
}

func newHandshaker(mux *Mux, cid wire.ConnID, raddr netip.AddrPort) *handshaker {
	return &handshaker{
		mux:    mux,
		id:     cid,
		closed: make(chan struct{}),
		in:     make(chan []byte, 1),
		raddr:  raddr,
	}
}

func (c *handshaker) handshake(hs sec.Handshake) error {
	err := c.handshakeImpl(hs)
	if err != nil {
		c.closeWithError(err)
	}
	return err
}

func (c *handshaker) handshakeImpl(hs sec.Handshake) error {
	{
		buf := make([]byte, maxPacketSize)
		copy(buf, c.id[:])
		buf[0] |= wire.HandshakePacket

		w := wire.NewWriter(buf[8:])
		cookie, _ := c.mux.jar.Load(c.raddr)
		if err := wire.EncodeLengthPrefixedBytes(w, cookie); err != nil {
			return err
		}
		var tmp bytes.Buffer
		if err := hs.WriteMessage(&tmp, nil); err != nil {
			return err
		}
		if err := wire.EncodeLengthPrefixedBytes(w, tmp.Bytes()); err != nil {
			return err
		}

		c.mux.pconn.WriteToUDPAddrPort(buf, c.raddr)
	}

	{
		var p []byte
		select {
		case p = <-c.in:
		case <-c.closed:
			return c.closeErr
		}

		r := wire.NewReader(p[8:])

		// Mux.handlePacket ensured that len(p) ≥ 8
		switch p[0] & 0xc0 {
		case wire.RetryPacket:
			// BUG: c.mux.jar may grow indefinitely, but this is likely to
			// not be a problem: we expect Mux to connect to few addresses
			// in its lifetime.
			c.mux.jar.Store(c.raddr, slices_Clone(p[8:]))
			return ErrAgain

		case wire.DataPacket:
			if _, err := hs.ReadMessage(r, 0); err != nil {
				return err
			}

		default:
			panic("unreachable")
		}
	}

	return nil
}

func (c *handshaker) handlePacket(p []byte, raddr netip.AddrPort) {
	select {
	case c.in <- slices_Clone(p):
	default:
	}
}

func (c *handshaker) closeWithError(err error) {
	c.once.Do(func() {
		c.mux.conns.Delete(c.id)
		c.closeErr = err
		close(c.closed)
	})
}
