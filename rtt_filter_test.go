package quic

import (
	"fmt"
	"testing"
	"time"
)

var rttFilterTests = [][]struct {
	rtt   time.Duration
	delay time.Duration
	now   time.Time

	minRTT      time.Duration
	minRTTRenew time.Time
	smoothedRTT time.Duration
	mdev        time.Duration
	latestRTT   time.Duration
}{
	{
		{
			rtt:   300 * time.Millisecond,
			delay: 100 * time.Millisecond,
			now:   time.Date(2000, 1, 1, 1, 1, 1, 0, time.UTC),

			minRTT:      300 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: 300 * time.Millisecond,
			mdev:        -1,
			latestRTT:   300 * time.Millisecond,
		},
		{
			rtt:   350 * time.Millisecond,
			delay: 50 * time.Millisecond,
			now:   time.Date(2000, 1, 1, 1, 1, 2, 0, time.UTC),

			minRTT:      300 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: 300 * time.Millisecond,
			mdev:        -1,
			latestRTT:   300 * time.Millisecond,
		},
		{
			rtt:   200 * time.Millisecond,
			delay: 300 * time.Millisecond,
			now:   time.Date(2000, 1, 1, 1, 1, 3, 0, time.UTC),

			minRTT:      200 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: 287500 * time.Microsecond,
			mdev:        -1,
			latestRTT:   200 * time.Millisecond,
		},
	},
	{
		{
			rtt:   200 * time.Millisecond,
			delay: 0,
			now:   time.Date(2000, 1, 1, 1, 1, 1, 0, time.UTC),

			minRTT:      200 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: -1,
			mdev:        -1,
			latestRTT:   -1,
		},
		{
			rtt:   10 * time.Millisecond,
			delay: 0,
			now:   time.Date(2000, 1, 1, 1, 1, 2, 0, time.UTC),

			minRTT:      10 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: -1,
			mdev:        -1,
			latestRTT:   -1,
		},
		{
			rtt:   50 * time.Millisecond,
			delay: 0,
			now:   time.Date(2000, 1, 1, 1, 1, 3, 0, time.UTC),

			minRTT:      10 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: -1,
			mdev:        -1,
			latestRTT:   -1,
		},
		{
			rtt:   100 * time.Millisecond,
			delay: 0,
			now:   time.Date(2000, 1, 1, 2, 1, 1, 0, time.UTC),

			minRTT:      100 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: -1,
			mdev:        -1,
			latestRTT:   -1,
		},
		{
			rtt:   7 * time.Millisecond,
			delay: 2 * time.Millisecond,
			now:   time.Date(2000, 1, 1, 2, 1, 2, 0, time.UTC),

			minRTT:      7 * time.Millisecond,
			minRTTRenew: time.Time{},
			smoothedRTT: -1,
			mdev:        -1,
			latestRTT:   -1,
		},
	},
}

func TestRTTFilter(t *testing.T) {
	for i, test := range rttFilterTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			rttFilter := newRTTFilter()

			for j, c := range test {
				rttFilter.Update(c.rtt, c.delay, c.now)

				if c.minRTT >= 0 && rttFilter.minRTT != c.minRTT {
					t.Errorf("%d: minRTT = %v, want %v", j, rttFilter.minRTT, c.minRTT)
				}
				if !c.minRTTRenew.IsZero() && !rttFilter.minRTTRenew.Equal(c.minRTTRenew) {
					t.Errorf("%d: minRTTRenew = %v, want %v", j, rttFilter.minRTTRenew, c.minRTTRenew)
				}
				if c.smoothedRTT >= 0 && rttFilter.smoothedRTT != c.smoothedRTT {
					t.Errorf("%d: smoothedRTT = %v, want %v", j, rttFilter.smoothedRTT, c.smoothedRTT)
				}
				if c.mdev >= 0 && rttFilter.mdev != c.mdev {
					t.Errorf("%d: mdev = %v, want %v", j, rttFilter.mdev, c.mdev)
				}
				if c.mdev >= 0 && rttFilter.latestRTT != c.latestRTT {
					t.Errorf("%d: latestRTT = %v, want %v", j, rttFilter.latestRTT, c.latestRTT)
				}

				if t.Failed() {
					break
				}
			}
		})
	}
}
