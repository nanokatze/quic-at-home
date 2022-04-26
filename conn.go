package quic

import (
	"io"
	"log"
	"math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/nanokatze/quic-at-home/internal/sec"
	"github.com/nanokatze/quic-at-home/internal/wire"
)

// Debugging
const (
	// noNacks disables nack-based loss detection.
	noNacks = false

	// noStreamOffImplicitAck disables a STREAM frame acking maximum stream
	// data offset to s.Off+len(s.Data).
	noStreamOffImplicitAck = false
)

// maxRcvdPacketNumberRangeCount limits how many received packet number ranges
// are kept track of.
//
// TODO: increase maxRcvdPacketNumberRangeCount when ACK can be truncated to
// fit the packet.
const maxRcvdPacketNumberRangeCount = 8

const maxAckedPacketNumberRangeCount = maxRcvdPacketNumberRangeCount

// maxTimeoutBackoff specifies the maximum timeout backoff, in powers of two.
const maxTimeoutBackoff = 5

// minMigrationProbeInterval specifies how often a migration probe can be sent,
// per connection.
const minMigrationProbeInterval = time.Second / 3

type Conn struct {
	mux *Mux
	id  wire.ConnID

	once     sync.Once
	closed   chan struct{}
	closeErr error

	// TODO: rename these

	relrcvready   chan struct{} // you've got data!
	relsndready   chan struct{}
	unrelrcvready chan struct{}
	unrelsndready chan struct{}
	wakeup        chan struct{}

	mu sync.Mutex // protects following fields

	recvAEAD, sendAEAD sec.AEAD

	// Packet number counter
	seq int64
	// Maximum packet number that the peer acked
	maxPNAcked wire.PacketNumber
	// The last several received packet number ranges, at most
	// maxRcvdPacketNumberRangeCount long.
	maxRcvdPNRanges wire.PacketNumberRanges
	// Time maxRcvdPNRanges.Max() was received.
	maxRcvdPNRcvTime time.Time
	// Packets that were sent and are not yet acked nor lost. Only includes
	// ack-eliciting packets.
	inFlightPackets map[wire.PacketNumber]inFlightPacket
	// ∑_pn inFlightPackets[pn].size
	inFlightBytes int

	congestionController *congestionController
	rttFilter            *rttFilter

	timeoutBackoff int
	timeout        time.Time // when time-based loss detection will be triggered

	sendAckBy   time.Time
	sentTailAck bool

	streamReassembler    *streamReassembler
	maxStreamOffAcked    int64 // max stream offset that the peer acked
	maxStreamOffInFlight int64

	streamFragments     []streamFragment
	streamOff           int64
	maxStreamOff        int64 // peer's max stream offset
	streamBytesInFlight int   // == ∑_pn ∑ᵢ len(inFlightPackets[pn].streamFragments[i].data) + ∑ᵢ len(streamFragments[i].data)

	msgReassembler *msgReassembler
	msgRcvdSeq     int64

	msgData      []byte
	msgSeq       int64
	msgContinued bool

	migrationAddr          netip.AddrPort
	migrationProbeCooldown time.Time

	raddr netip.AddrPort

	// Experimental stats. Stats could be evolved in two ways:
	//
	// 1) we will introduce a tracing interface (with tracing level
	//    selectable at compile time) that would be useful for testing,
	//    mocking and could happen to be useful for counting stats too,
	//    or
	//
	// 2) just the stats counters. For better ergonomics, stats should be
	//    an int64 array indexed by a enum.

	bytesRcvd          int64
	streamBytesRead    int64
	msgBytesRead       int64
	msgBytesRcvd       int64
	bytesSent          int64
	bytesNacked        int64
	bytesTimedOut      int64
	tailAcksSent       int64
	streamBytesWritten int64
	msgBytesWritten    int64
}

type inFlightPacket struct {
	maxPNAcks       wire.PacketNumber // max packet number this packet acknowledges
	maxStreamOff    int64
	streamFragments []streamFragment
	containsMsg     bool
	paddr           netip.AddrPort
	sent            time.Time
	size            int
}

func (p inFlightPacket) AckEliciting() bool {
	return p.maxStreamOff > 0 || len(p.streamFragments) > 0 || p.containsMsg || p.paddr.IsValid()
}

type streamFragment struct {
	data []byte
	off  int64
}

func (f streamFragment) Split(i int) (streamFragment, streamFragment) {
	g := streamFragment{
		data: f.data[i:],
		off:  f.off + int64(i),
	}
	f.data = f.data[:i]
	return f, g
}

func newConn(mux *Mux, cid wire.ConnID, recvAEAD, sendAEAD sec.AEAD, raddr netip.AddrPort) *Conn {
	c := &Conn{
		mux: mux,
		id:  cid,

		closed: make(chan struct{}),

		relrcvready:   make(chan struct{}, 1),
		relsndready:   make(chan struct{}, 1),
		unrelrcvready: make(chan struct{}, 1),
		unrelsndready: make(chan struct{}, 1),
		wakeup:        make(chan struct{}, 1),

		recvAEAD: recvAEAD,
		sendAEAD: sendAEAD,

		seq: rand.Int63n(3),

		maxPNAcked: -1,

		inFlightPackets: make(map[wire.PacketNumber]inFlightPacket),

		streamReassembler: newStreamReassembler(mux.config.StreamReceiveWindow),

		msgReassembler: newMsgReassembler(0),
		msgRcvdSeq:     -2,

		msgSeq: rand.Int63n(3),
	}
	c.setRemoteAddr(raddr, time.Time{})

	return c
}

func (c *Conn) setRemoteAddr(raddr netip.AddrPort, now time.Time) {
	c.congestionController = newCongestionController(now)
	c.rttFilter = newRTTFilter()

	c.migrationAddr = netip.AddrPort{}
	c.migrationProbeCooldown = now.Add(minMigrationProbeInterval)

	c.raddr = raddr
}

// If c is closed, Read will read remaining stream contents before reporting an
// error.
func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		n, _ := c.streamReassembler.Read(b)
		if n == 0 {
			c.mu.Unlock()
			select {
			case <-c.relrcvready:
				c.mu.Lock()
				continue
			case <-c.closed:
				c.mu.Lock()
				return 0, c.closeErr
			}
		}

		select {
		case c.wakeup <- struct{}{}:
		default:
		}
		c.streamBytesRead += int64(n)
		return n, nil
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	select {
	default:
	case <-c.closed:
		return 0, c.closeErr
	}

	// TODO: evaluate whether to optimize for small writes

	// Avoid retaining b.
	b = slices_Clone(b)

	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for n < len(b) {
		nn := min(int(min(int64(len(b)-n), c.maxStreamOff-c.streamOff)), c.mux.config.MaxStreamBytesInFlight-c.streamBytesInFlight)
		if nn == 0 {
			c.mu.Unlock()
			select {
			case <-c.relsndready:
				c.mu.Lock()
				continue
			case <-c.closed:
				c.mu.Lock()
				return n, c.closeErr
			}
		}

		if wire.MaxVarint-c.streamOff < int64(nn) {
			panic("stream offset wraparound")
		}
		c.streamFragments = append(c.streamFragments, streamFragment{
			data: b[n : n+nn],
			off:  c.streamOff,
		})
		c.streamOff += int64(nn)
		c.streamBytesInFlight += nn

		select {
		case c.wakeup <- struct{}{}:
		default:
		}

		c.streamBytesWritten += int64(nn)

		n += nn
	}
	return n, nil
}

// SetMsgReceiveWindow sets the receive window size of the message ReadWriter.
// SetMsgReceiveWindow must not be called while the message ReadWriter is being
// read or written to.
func (c *Conn) SetMsgReceiveWindow(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgReassembler = newMsgReassembler(n)
}

func (c *Conn) ReadMsg(b []byte) (int, error) {
	select {
	case <-c.unrelrcvready:
	case <-c.closed:
		return 0, c.closeErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	n, _ := c.msgReassembler.Read(b)
	c.msgBytesRead += int64(n)
	return n, nil
}

func (c *Conn) WriteMsg(b []byte) (int, error) {
	select {
	case c.unrelsndready <- struct{}{}:
	case <-c.closed:
		return 0, c.closeErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgData = slices_Clone(b)
	c.msgContinued = false

	select {
	case c.wakeup <- struct{}{}:
	default:
	}
	c.msgBytesWritten += int64(len(b))
	return len(b), nil
}

func (c *Conn) ReadMsgFrom(r io.Reader, max int) (int, error) {
	select {
	case c.unrelsndready <- struct{}{}:
	case <-c.closed:
		return 0, c.closeErr
	}

	msgBuf := make([]byte, max)

	n, err := r.Read(msgBuf)
	if err != nil {
		// Let someone else send
		select {
		case <-c.unrelsndready:
		default:
			panic("unreachable")
		}
		return 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgData = msgBuf[:n]
	c.msgContinued = false

	select {
	case c.wakeup <- struct{}{}:
	default:
	}
	c.msgBytesWritten += int64(n)
	return n, nil
}

func (c *Conn) run() {
	timer := time.NewTimer(0)
	defer timer.Stop()

	// Avoid thrashing c.mux.closed by repeated enqueues and
	// dequeues.
	go func() {
		select {
		case <-c.mux.closed:
			c.Close()
		case <-c.closed:
		}
	}()

	for {
		select {
		case <-timer.C:
		case <-c.wakeup:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-c.closed:
			return
		}

		sleepUntil := c.wake()
		if sleepUntil < forever {
			timer.Reset(sleepUntil)
		}
	}
}

func (c *Conn) wake() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	c.maybeScavengeTimedOutPackets(now)

	buf := make([]byte, maxPacketSize) // TODO: sync.Pool for superbuffers?
	off := 0
	for {
		// TODO: this condition doesn't seem necessary, could just use
		// append in a more clever way
		if len(buf) < off+maxPacketSize {
			buf = append(buf, make([]byte, maxPacketSize)...)
		}

		n, paddr := c.sendPacket(buf[off:off+maxPacketSize], now)
		if paddr.IsValid() {
			c.mux.pconn.WriteToUDPAddrPort(buf[off:off+n], paddr)
		}
		if n < maxPacketSize {
			// TODO: flush buffer when the size gets to around 65k
			c.mux.pconn.WriteToUDPAddrPortGSO(buf[:off+n], maxPacketSize, c.raddr)
			break
		}

		select {
		case <-c.closed:
			return forever
		default:
		}

		off += n
	}

	sleepUntil := forever
	for _, t := range []time.Time{
		c.timeout,
		c.sendAckBy,
	} {
		sleepUntil = min(sleepUntil, t.Sub(now))
	}
	return sleepUntil
}

func (c *Conn) maybeScavengeTimedOutPackets(now time.Time) {
	if c.timeout.IsZero() || now.Before(c.timeout) {
		return
	}

	lossThresh := c.rttFilter.LossDurationThreshold()

	backoff := false
	ackElicitingPacketsInFlight := false
	for pn, p := range c.inFlightPackets {
		ackElicitingPacketsInFlight = true
		if now.Sub(p.sent) < lossThresh {
			// The packet has not been in-flight for long
			// enough.
			continue
		}

		delete(c.inFlightPackets, pn)
		c.inFlightBytes -= p.size

		c.congestionController.Loss(p.sent, now)

		if c.maxStreamOffInFlight == p.maxStreamOff {
			// This packet carried the maximum STREAM_MAX_OFFSET
			// we've sent. We don't know what the one before it was,
			// nor does it matter, just set the in-flight offset to
			// something low.
			c.maxStreamOffInFlight = 0
		}

		// TODO: keep c.streamFragments sorted
		c.streamFragments = append(p.streamFragments, c.streamFragments...)

		c.bytesTimedOut += int64(p.size)

		// A packet timed out likely because of a congested link,
		// backoff.
		backoff = true
	}

	if backoff && c.timeoutBackoff < maxTimeoutBackoff {
		c.timeoutBackoff++
	}
	if ackElicitingPacketsInFlight {
		c.timeout = now.Add(c.rttFilter.PTO() << c.timeoutBackoff)
	} else {
		c.timeout = time.Time{}
	}
}

func (c *Conn) Close() error {
	c.closeWithError(io.ErrClosedPipe)
	return nil
}

func (c *Conn) closeWithError(err error) {
	c.once.Do(func() {
		c.mux.conns.Delete(c.id)
		c.closeErr = err
		close(c.closed)

		c.mu.Lock()
		buf := make([]byte, maxPacketSize)
		n, _ := c.sendPacket(buf, time.Now()) // send CLOSE
		c.mux.pconn.WriteToUDPAddrPort(buf[:n], c.raddr)
		c.mu.Unlock()

		log.Print("bytes rcvd           ", c.bytesRcvd)
		log.Print("stream bytes read    ", c.streamBytesRead)
		log.Print("msg bytes read       ", c.msgBytesRead)
		log.Print("msg bytes rcvd       ", c.msgBytesRcvd)
		log.Print("bytes sent           ", c.bytesSent)
		log.Print("bytes acked          ", c.bytesSent-c.bytesNacked-c.bytesTimedOut)
		log.Print("bytes nacked         ", c.bytesNacked)
		log.Print("bytes timed out      ", c.bytesTimedOut)
		log.Print("tail acks sent       ", c.tailAcksSent)
		log.Print("stream bytes written ", c.streamBytesWritten)
		log.Print("msg bytes written    ", c.msgBytesWritten)
		log.Printf("overhead %.2f%% loss %.2f%%",
			100.0*(1.0-float64(c.streamBytesWritten+c.msgBytesWritten)/float64(c.bytesSent-c.bytesNacked-c.bytesTimedOut)),
			100.0*(float64(c.bytesNacked+c.bytesTimedOut)/float64(c.bytesSent-c.bytesNacked-c.bytesTimedOut)))
	})
}
