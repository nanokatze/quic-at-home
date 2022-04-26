package quic

import (
	"math"
	"time"
)

// initialRTT is the initial RTT estimate used by RTT filter.
const initialRTT = 300 * time.Millisecond

// Window size of RTT min filter.
const minRTTWnd = time.Minute

// rttFilter is an implementation of RFC 6298 with some modifications.
type rttFilter struct {
	minRTT      time.Duration
	minRTTRenew time.Time
	smoothedRTT time.Duration
	mdev        time.Duration
	latestRTT   time.Duration
}

func newRTTFilter() *rttFilter { return &rttFilter{} }

func (rf *rttFilter) Update(rtt, delay time.Duration, now time.Time) {
	const α, β = 0.125, 0.25 // gain

	if rf.minRTT > rtt || !rf.minRTTRenew.After(now) {
		rf.minRTT = rtt
		rf.minRTTRenew = now.Add(minRTTWnd)
	}
	if rf.smoothedRTT > 0 {
		if rtt-delay >= rf.minRTT {
			rtt -= delay
		}
		rf.mdev = roundToEvenDuration(lerp(float64(rf.mdev), math.Abs(float64(rf.smoothedRTT-rtt)), β))
		rf.smoothedRTT = roundToEvenDuration(lerp(float64(rf.smoothedRTT), float64(rtt), α))
	} else {
		rf.smoothedRTT = rtt
		rf.mdev = rtt / 2
	}
	rf.latestRTT = rtt
}

func (rf *rttFilter) LossDurationThreshold() time.Duration {
	rtt := max(rf.smoothedRTT, rf.latestRTT)
	if rtt == 0 {
		rtt = initialRTT
	}
	return max(roundToEvenDuration(1.125*float64(rtt)), timerGranularity)
}

func (rf *rttFilter) PTO() time.Duration {
	smoothedRTT, mdev := rf.smoothedRTT, rf.mdev
	if smoothedRTT == 0 {
		smoothedRTT, mdev = initialRTT, initialRTT/2
	}
	return smoothedRTT + max(4*mdev, timerGranularity) + maxAckDelay
}

func lerp(x, y, a float64) float64 {
	return x + a*(y-x)
}

func roundToEvenDuration(x float64) time.Duration {
	return time.Duration(math.RoundToEven(x))
}
