package quic

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nanokatze/quic-at-home/internal/cookie"
	"github.com/nanokatze/quic-at-home/internal/sec"
	"github.com/nanokatze/quic-at-home/internal/udp"
	"github.com/nanokatze/quic-at-home/internal/wire"
)

var ErrAgain = errors.New("try again")

type abstractUDPConn interface {
	Close() error
	LocalAddr() net.Addr
	ReadFromUDPAddrPortGRO([]byte) (int, int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	WriteToUDPAddrPortGSO([]byte, int, netip.AddrPort) (int, error)
}

type Mux struct {
	pconn  abstractUDPConn
	config *Config

	authRenewer *time.Ticker
	auth        *cookie.Authenticator
	jar         syncMap[netip.AddrPort, []byte]

	once     sync.Once
	closed   chan struct{}
	closeErr error

	accept chan *Conn

	conns syncMap[wire.ConnID, packetHandler]
}

type packetHandler interface {
	handlePacket([]byte, netip.AddrPort)
}

// cookieAuthRenewalInterval is the time between updates of the cookie
// authenticator's key.
//
// For the clients that need to present a valid cookie in an initial packet,
// cookieAuthRenewalInterval puts an upper bound on the time a cookie is valid.
const cookieAuthRenewalInterval = 2 * time.Minute

// backlog specifies the capacity of the queue of incoming connections ready to
// be accepted using the Accept call.
const backlog = 3

func ListenAddrPort(laddr netip.AddrPort, config *Config) (*Mux, error) {
	pconn, err := udp.ListenAddrPort(laddr)
	if err != nil {
		return nil, err
	}

	m := &Mux{
		pconn:  pconn,
		config: config,

		authRenewer: time.NewTicker(cookieAuthRenewalInterval),

		closed: make(chan struct{}),

		accept: make(chan *Conn, backlog),
	}
	go m.run()
	return m, nil
}

func (m *Mux) LocalAddrPort() netip.AddrPort {
	return m.pconn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (m *Mux) Accept() (*Conn, error) {
	select {
	case c := <-m.accept:
		return c, nil

	case <-m.closed:
		return nil, m.closeErr
	}
}

// DialContextAddrPort dials raddr. Note that when DialContextAddrPort returns,
// peer might not have completed the handshake.
//
// See github.com/nanokatze/quic-at-home/transportutil.Dial for a more convenient interface.
func (m *Mux) DialContextAddrPort(ctx context.Context, remoteStaticPublicKey PublicKey, raddr netip.AddrPort) (*Conn, error) {
	cid, err := readConnID(cryptorand.Reader)
	if err != nil {
		panic(err)
	}

	c := newHandshaker(m, cid, raddr)
	if _, ok := c.mux.conns.LoadOrStore(cid, c); ok {
		return nil, ErrAgain
	}

	hs := sec.NewHandshake(noisePrologue, m.config.PrivateKey, remoteStaticPublicKey, cryptorand.Reader, sec.InitiatorRole)

	done := make(chan error)
	go func() { done <- c.handshake(hs) }()

	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
		c1, c2, _ := hs.Split()
		c := newConn(m, cid, c2, c1, raddr)
		m.conns.Store(cid, c)
		go c.run()
		return c, nil

	case <-ctx.Done():
		err := ctx.Err()
		c.closeWithError(err)
		return nil, err
	}
}

func (m *Mux) run() {
	buf := make([]byte, 65536) // TODO: add a literal for this constant

	for {
		n, ss, raddr, err := m.pconn.ReadFromUDPAddrPortGRO(buf)
		if err != nil {
			m.closeWithError(err)
			return
		}

		for i := 0; i < n; i += ss {
			m.handlePacket(buf[i:i+min(ss, n-i)], raddr)
		}
	}
}

func (m *Mux) handlePacket(p []byte, raddr netip.AddrPort) {
	// Too short: a packet must at least have a connection ID and some
	// payload.
	if len(p) < 8 {
		return
	}

	cid := *(*wire.ConnID)(p[0:8])
	cid[0] &^= 0xc0

	switch p[0] & 0xc0 {
	case wire.HandshakePacket:
		if m.config.Listen && len(p) == maxPacketSize {
			m.receiveHandshake(p, raddr)
		}

	case wire.RetryPacket, wire.DataPacket:
		if c, ok := m.conns.Load(cid); ok {
			c.handlePacket(p, raddr)
		}
	}
}

func (m *Mux) receiveHandshake(p []byte, raddr netip.AddrPort) {
	_ = p[maxPacketSize-1]

	cid := *(*wire.ConnID)(p[0:8])
	cid[0] &^= 0xc0

	r := wire.NewReader(p[8:])

	cookie, err := wire.DecodeLengthPrefixedBytes(r)
	if err != nil {
		return
	}
	data, err := wire.DecodeLengthPrefixedBytes(r)
	if err != nil {
		return
	}

	select {
	case <-m.authRenewer.C:
		m.auth = nil
	default:
	}
	if m.auth == nil {
		m.auth = newAuthenticatorOrPanic()
	}

	ad := []byte(raddr.String())
	if !m.auth.Verify(cookie, ad) {
		fresh := m.auth.MustSign(nil, ad)

		buf := make([]byte, maxPacketSize)
		copy(buf, cid[:])
		buf[0] |= wire.RetryPacket

		w := wire.NewWriter(buf[8:])
		if _, err := w.Write(fresh); err != nil {
			panic(err)
		}

		m.pconn.WriteToUDPAddrPort(buf[:8+w.Len()], raddr)

		return
	}

	hs := sec.NewHandshake(noisePrologue, m.config.PrivateKey, nil, cryptorand.Reader, sec.ResponderRole)
	if _, err := hs.ReadMessage(bytes.NewReader(data), 0); err != nil {
		return
	}

	buf := make([]byte, maxPacketSize)
	copy(buf, cid[:])
	buf[0] |= wire.DataPacket

	w := wire.NewWriter(buf[8:])
	if err := hs.WriteMessage(w, nil); err != nil {
		return
	}

	c1, c2, _ := hs.Split()
	c := newConn(m, cid, c1, c2, raddr)
	// If we already have a connection with the same ID, ignore this
	// connection attempt.
	if _, ok := m.conns.LoadOrStore(cid, c); ok {
		return
	}
	select {
	case m.accept <- c:
		go c.run()

		m.pconn.WriteToUDPAddrPort(buf[:8+w.Len()], raddr)

	default:
		m.conns.Delete(cid)
	}
}

// Close shutdowns the Mux and its connections. Close does not close the
// connections gracefully -- peers might not observe a CLOSE frame. If graceful
// shutdown is desired, close each connection before closing the Mux.
func (m *Mux) Close() error {
	m.closeWithError(io.ErrClosedPipe)
	return nil
}

func (m *Mux) closeWithError(err error) {
	m.once.Do(func() {
		// We can't close the connections here because we're not seeing
		// a consistent snapshot of conns. Each conn will have to close
		// on their own.

		m.closeErr = err
		close(m.closed)
		m.authRenewer.Stop()
		m.pconn.Close()
	})
}

func newAuthenticatorOrPanic() *cookie.Authenticator {
	a, err := cookie.NewAuthenticator(cryptorand.Reader)
	if err != nil {
		panic(err) // should not happen
	}
	return a
}

func readConnID(r io.Reader) (wire.ConnID, error) {
	var cid [8]byte
	if _, err := io.ReadFull(r, cid[:]); err != nil {
		return wire.ConnID{}, err
	}
	cid[0] &^= 0xc0
	return wire.ConnID(cid), nil
}
