package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/nanokatze/quic-at-home/internal/wire"
)

func (c *Conn) handlePacket(p []byte, raddr netip.AddrPort) {
	if p[0]&0xc0 != wire.DataPacket {
		return
	}
	if len(p) < 12 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.handlePacketImpl(p, raddr, time.Now()); err != nil {
		if err != io.ErrClosedPipe {
			err = fmt.Errorf("protocol botch: %v", err)
		}
		c.mu.Unlock()
		c.closeWithError(err)
		c.mu.Lock()
	}
}

func (c *Conn) handlePacketImpl(p []byte, raddr netip.AddrPort, now time.Time) error {
	maxRcvdPN := c.maxRcvdPNRanges.Max()

	pn := guessPacketNumber(maxRcvdPN, binary.LittleEndian.Uint32(p[8:12]))

	payload, err := c.recvAEAD.Open(p[12:12], uint64(pn), p[12:], p[0:8])
	if err != nil {
		return nil
	}

	ackEliciting := false
	for r := wire.NewReader(payload); r.Remaining() > 0; {
		t := r.PeekByte()

		switch {
		case t == 0b00000000: // TODO: wire.IsPadding
			r.ReadByte()

		case wire.IsPing(t):
			_, err := wire.DecodePing(r)
			if err != nil {
				return fmt.Errorf("decode PING: %v", err)
			}

		case wire.IsAck(t):
			ack, err := wire.DecodeAck(r, maxAckedPacketNumberRangeCount)
			if err != nil {
				return fmt.Errorf("decode ACK: %v", err)
			}

			if err := c.handleAck(ack, raddr, now); err != nil {
				return err
			}

		case wire.IsStream(t):
			s, err := wire.DecodeStream(r)
			if err != nil {
				return fmt.Errorf("decode STREAM: %v", err)
			}

			if err := c.handleStream(s); err != nil {
				return err
			}

		case wire.IsMaxStreamData(t):
			off, err := wire.DecodeMaxStreamData(r)
			if err != nil {
				return fmt.Errorf("decode MAX_STREAM_DATA: %v", err)
			}

			c.handleMaxStreamData(off)

		case wire.IsMsg(t):
			m, err := wire.DecodeMsg(r)
			if err != nil {
				return fmt.Errorf("decode MSG: %v", err)
			}

			c.handleMsg(m)

		case wire.IsClose(t):
			return io.ErrClosedPipe

		default:
			return fmt.Errorf("unknown frame 0x%02x", t)
		}

		if maxRcvdPN < pn && (t != 0b00000000 && !wire.IsAck(t)) { // TODO: move this into wire.IsAckEliciting
			ackEliciting = true
		}
	}

	if maxRcvdPN < pn {
		// TODO: make this not ugly
		if len(c.maxRcvdPNRanges) == 0 || c.maxRcvdPNRanges[0].Max+1 < pn {
			c.maxRcvdPNRanges = append(wire.PacketNumberRanges{{pn, pn}}, c.maxRcvdPNRanges...)
		} else if c.maxRcvdPNRanges[0].Max+1 == pn {
			c.maxRcvdPNRanges[0].Max = pn
		}
		if len(c.maxRcvdPNRanges) > maxRcvdPacketNumberRangeCount {
			c.maxRcvdPNRanges = c.maxRcvdPNRanges[:maxRcvdPacketNumberRangeCount]
		}
		c.maxRcvdPNRcvTime = now
	}

	switch {
	case maxRcvdPN+1 < pn:
		// Likely loss, send ACK ASAP
		c.sendAckBy = now

	case maxRcvdPN+1 == pn:
		if ackEliciting {
			if c.sendAckBy.IsZero() {
				c.sendAckBy = now.Add(maxAckDelay - timerGranularity)
			} else {
				// Send ACK immediately every now and then.
				c.sendAckBy = now
			}
		}
	}

	if c.raddr != raddr && maxRcvdPN < pn {
		c.migrationAddr = raddr
	}

	select {
	case c.wakeup <- struct{}{}:
	default:
	}

	c.bytesRcvd += int64(len(p))
	return nil
}

func (c *Conn) handleAck(ack wire.Ack, raddr netip.AddrPort, now time.Time) error {
	maxPNAcks := ack.Ranges.Max()
	if maxPNAcks >= wire.PacketNumber(c.seq) {
		return errors.New("optimistic ack")
	}

	if p, ok := c.inFlightPackets[maxPNAcks]; ok && c.maxPNAcked < maxPNAcks {
		// Acking migration will reset the RTT filter, do it before
		// sampling RTT.

		if p.paddr == raddr {
			c.setRemoteAddr(raddr, now)
		} else {
			// Abort migration
			c.migrationAddr = netip.AddrPort{}
		}

		c.rttFilter.Update(now.Sub(p.sent), min(ack.Delay, maxAckDelay), now)
	}

	ackElicitingPacketsInFlight := false
	for pn, p := range c.inFlightPackets {
		switch {
		case ack.Ranges.Contains(pn): // ack
			c.maxPNAcked = max(c.maxPNAcked, pn)
			c.maxRcvdPNRanges = c.maxRcvdPNRanges.TrimLesser(p.maxPNAcks)

			delete(c.inFlightPackets, pn)
			c.inFlightBytes -= p.size

			c.congestionController.Ack(p.size, p.sent, now)

			c.maxStreamOffAcked = max(c.maxStreamOffAcked, p.maxStreamOff)

			for _, f := range p.streamFragments {
				c.streamBytesInFlight -= len(f.data)
			}
			if len(p.streamFragments) > 0 {
				// Unblock the user if they were blocked on the
				// MaxStreamBytesInFlight limit.
				select {
				case c.relsndready <- struct{}{}:
				default:
				}
			}

		case pn < maxPNAcks && !noNacks: // nack
			delete(c.inFlightPackets, pn)
			c.inFlightBytes -= p.size

			c.congestionController.Loss(p.sent, now)

			if c.maxStreamOffInFlight == p.maxStreamOff {
				c.maxStreamOffInFlight = 0
			}

			// TODO: keep c.streamFragments sorted
			c.streamFragments = append(p.streamFragments, c.streamFragments...)

			c.bytesNacked += int64(p.size)

		default:
			ackElicitingPacketsInFlight = true
		}
	}

	if ackElicitingPacketsInFlight {
		c.timeoutBackoff = 0
		c.timeout = now.Add(c.rttFilter.PTO() << c.timeoutBackoff)
	}

	return nil
}

func (c *Conn) handleMaxStreamData(off wire.MaxStreamData) {
	if c.maxStreamOff < int64(off) {
		c.maxStreamOff = int64(off)

		// Unblock the user if they were blocked.
		select {
		case c.relsndready <- struct{}{}:
		default:
		}
	}
}

func (c *Conn) handleStream(s wire.Stream) error {
	// It is ok if s.Off+int64(len(s.Data)) > c.maxStreamOffAcked: the peer
	// could've successfuly received MAX_STREAM_OFFSET, but the packet
	// acking the MAX_STREAM_OFFSET was lost.
	if _, err := c.streamReassembler.WriteAt(s.Data, s.Off); err != nil {
		return err
	}
	if !noStreamOffImplicitAck {
		c.maxStreamOffAcked = max(c.maxStreamOffAcked, s.Off+int64(len(s.Data)))
	}

	if c.streamReassembler.CanBeRead() {
		select {
		case c.relrcvready <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *Conn) handleMsg(m wire.Msg) {
	if m.First && c.msgRcvdSeq < m.Seq {
		c.msgReassembler.Clear()
	} else if c.msgRcvdSeq+1 != m.Seq {
		// Out of order
		return
	}

	if _, err := c.msgReassembler.Write(m.Data); err != nil {
		// The message is bigger than our receive window
		return
	}
	c.msgRcvdSeq = m.Seq

	if m.Last {
		c.msgReassembler.Swap()

		select {
		case c.unrelrcvready <- struct{}{}:
		default:
		}
	}

	c.msgBytesRcvd += int64(len(m.Data))
}
