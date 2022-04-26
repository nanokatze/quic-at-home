package quic

import "time"

const initialCwnd = 2 * maxPacketSize

type congestionController struct {
	cwnd      int
	congested time.Time
	validated time.Time
}

func newCongestionController(now time.Time) *congestionController {
	return &congestionController{
		cwnd:      initialCwnd,
		congested: now, // avoid having packets sent with the old congestion controller contribute
		validated: now,
	}
}

func (c *congestionController) Ack(size int, sent, now time.Time) {
	if !sent.Before(c.congested) {
		c.cwnd += size
	}
}

func (c *congestionController) Loss(sent, now time.Time) {
	if !sent.Before(c.congested) {
		c.cwnd = initialCwnd
		c.congested = now
	}
}

func (c *congestionController) validatedCwnd(inFlightBytes int, pto time.Duration, now time.Time) int {
	cwnd := c.cwnd
	t := c.validated.Add(pto)
	for inFlightBytes+maxPacketSize < cwnd/2 && t.Before(now) {
		cwnd /= 2
		t = t.Add(pto)
	}
	return max(cwnd, initialCwnd)
}

func (c *congestionController) CwndLimited(inFlightBytes int, pto time.Duration, now time.Time) bool {
	return inFlightBytes+maxPacketSize > c.validatedCwnd(inFlightBytes, pto, now)
}

func (c *congestionController) Validate(inFlightBytes int, pto time.Duration, now time.Time) {
	c.cwnd = c.validatedCwnd(inFlightBytes, pto, now)
	c.validated = now
}
