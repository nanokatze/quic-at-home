package quic

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"time"

	"github.com/nanokatze/quic-at-home/internal/wire"
)

func (c *Conn) nextPacketNumber() wire.PacketNumber {
	pn := c.seq
	if pn == wire.MaxPacketNumber {
		panic("packet number wraparound")
	}
	c.seq++
	return wire.PacketNumber(pn)
}

func (c *Conn) sendPacket(dst []byte, now time.Time) (int, netip.AddrPort /* probe addr */) {
	copy(dst[:8], c.id[:])
	dst[0] |= wire.DataPacket

	w := wire.NewWriter(dst[12 : maxPacketSize-16])

	var p inFlightPacket

	select {
	case <-c.closed:
		c.sendClose(w)

	default:
		cwndLimited := c.congestionController.CwndLimited(c.inFlightBytes, c.rttFilter.PTO(), now)

		c.maybeSendAck(w, &p, cwndLimited, now)
		if cwndLimited {
			break
		}

		c.maybeSendMaxStreamOffset(w, &p)

		if rand.Int()&1 == 0 {
			c.maybeSendStream(w, &p)
			c.maybeSendMsg(w, &p)
		} else {
			c.maybeSendMsg(w, &p)
			c.maybeSendStream(w, &p)
		}
	}

	if c.migrationAddr.IsValid() && !c.migrationProbeCooldown.Before(now) {
		c.migrationProbeCooldown = now.Add(minMigrationProbeInterval)

		// If the packet isn't ack-eliciting, we need to make it one.
		if !p.AckEliciting() {
			if err := (wire.Ping{}).Encode(w); err != nil {
				panic(err)
			}
		}

		p.paddr = c.migrationAddr
	}

	if w.Len() == 0 {
		return 0, netip.AddrPort{} // nothing to send
	}

	p.sent = now

	// Fill in packet size. The real packet size has additional unknown C
	// bytes of overhead. Underestimating C will cause the congestion window
	// to be overshot at smaller packet sizes, but this is not a problem in
	// practice, as small packets are infrequent.
	p.size = 12 + w.Len() + 16

	pn := c.nextPacketNumber()

	if p.AckEliciting() {
		c.inFlightPackets[pn] = p
		c.inFlightBytes += p.size

		c.congestionController.Validate(c.inFlightBytes, c.rttFilter.PTO(), now)

		c.timeout = now.Add(c.rttFilter.PTO() << c.timeoutBackoff)

		c.bytesSent += int64(12 + w.Len() + 16)
	}

	// Fill in the packet number
	binary.LittleEndian.PutUint32(dst[8:12], uint32(pn))

	// Seal
	c.sendAEAD.Seal(dst[12:12], uint64(pn), dst[12:12+w.Len()], c.id[:])

	return 12 + w.Len() + 16, p.paddr
}

func (c *Conn) maybeSendAck(w *wire.Writer, p *inFlightPacket, cwndLimited bool, now time.Time) {
	if len(c.maxRcvdPNRanges) == 0 {
		return // nothing to ack
	}

	if !c.sendAckBy.IsZero() && !now.Before(c.sendAckBy) || cwndLimited && !c.sentTailAck {
		if err := (wire.Ack{
			Delay:  min(now.Sub(c.maxRcvdPNRcvTime), maxAckDelay),
			Ranges: c.maxRcvdPNRanges,
		}).Encode(w); err != nil {
			panic(err)
		}

		c.sendAckBy = time.Time{}
		if cwndLimited {
			c.sentTailAck = true

			c.tailAcksSent++
		}

		p.maxPNAcks = c.maxRcvdPNRanges.Max()
	}
	if !cwndLimited {
		// Not congested anymore
		c.sentTailAck = false
	}
}

func (c *Conn) maybeSendMaxStreamOffset(w *wire.Writer, p *inFlightPacket) {
	off := c.streamReassembler.MaxOffset()
	if c.maxStreamOffAcked < off && c.maxStreamOffInFlight < off {
		c.maxStreamOffInFlight = off

		if err := wire.MaxStreamData(off).Encode(w); err != nil {
			panic(err)
		}

		p.maxStreamOff = off
	}
}

func (c *Conn) maybeSendStream(w *wire.Writer, p *inFlightPacket) {
	for len(c.streamFragments) > 0 {
		// TODO: coalesce fragments for less wire overhead
		f := c.streamFragments[0]

		n, explicitLen := wire.StreamMaxDataLen(w.Remaining(), f.off, len(f.data))
		if n == len(f.data) {
			c.streamFragments = c.streamFragments[1:]
		} else if n > 0 {
			f, c.streamFragments[0] = f.Split(n)
		} else {
			// TODO: explain why it is ok to retain c.streamFragments
			break
		}

		if err := (wire.Stream{
			Off:  f.off,
			Data: f.data,
		}).Encode(w, explicitLen); err != nil {
			panic(err)
		}

		p.streamFragments = append(p.streamFragments, f)
	}
}

func (c *Conn) maybeSendMsg(w *wire.Writer, p *inFlightPacket) {
	n, explicitLen := wire.MsgMaxDataLen(w.Remaining(), c.msgSeq, len(c.msgData))
	if n == 0 {
		return // nothing to send or wouldn't fit
	}

	first := !c.msgContinued
	c.msgContinued = true

	last := n == len(c.msgData)

	data := c.msgData[:n]
	c.msgData = c.msgData[n:]

	seq := c.msgSeq
	if c.msgSeq == wire.MaxVarint {
		panic("message sequence number wraparound")
	}
	c.msgSeq++

	if err := (wire.Msg{
		First: first,
		Last:  last,
		Seq:   seq,
		Data:  data,
	}).Encode(w, explicitLen); err != nil {
		panic(err)
	}

	if len(c.msgData) == 0 {
		c.msgData = nil // allow GC

		select {
		case <-c.unrelsndready:
		default:
			panic("unreachable")
		}
	}

	p.containsMsg = true
}

func (c *Conn) sendClose(w *wire.Writer) {
	if err := (wire.Close{}).Encode(w); err != nil {
		panic(err)
	}
}
