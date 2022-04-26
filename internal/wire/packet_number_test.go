package wire

import (
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkPacketNumberRangesContains(b *testing.B) {
	r := rand.New(rand.NewSource(42))

	j := 1
	for {
		b.Run(fmt.Sprintf("%d", j), func(b *testing.B) {
			var ranges PacketNumberRanges

			maxPN := PacketNumber(r.Int63n(64))
			for i := 0; i < j; i++ {
				lo := maxPN
				hi := lo + PacketNumber(r.Int63n(64))
				ranges = append(ranges, PacketNumberRange{lo, hi})
				maxPN = hi + 1 /* at least 1 packet apart */ + PacketNumber(r.Int63n(63))
			}

			for i := 0; i < len(ranges)/2; i++ {
				ranges[i], ranges[len(ranges)-1-i] = ranges[len(ranges)-1-i], ranges[i]
			}

			for i := 0; i < 100; i++ {
				pn := PacketNumber(r.Int63n(int64(maxPN)))
				ok1 := containsLinearSearch(ranges, pn)
				ok2 := containsBinarySearch(ranges, pn)
				if ok1 != ok2 {
					b.Fatalf("linear and binary disagree for %v in %v", pn, ranges)
				}
			}

			b.Run("linear", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pn := PacketNumber(r.Int63n(int64(maxPN)))
					containsLinearSearch(ranges, pn)
				}
			})

			b.Run("binary", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					pn := PacketNumber(r.Int63n(int64(maxPN)))
					containsBinarySearch(ranges, pn)
				}
			})
		})

		if j > 1000 {
			break
		}
		j = j*3/2 + 1
	}
}

func containsLinearSearch(ranges PacketNumberRanges, pn PacketNumber) bool {
	for _, r := range ranges {
		if r.Contains(pn) {
			return true
		}
	}
	return false
}

func containsBinarySearch(ranges PacketNumberRanges, pn PacketNumber) bool {
	f := func(i int) bool { return ranges[i].Min <= pn }
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, len(ranges)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if !f(h) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i < len(ranges) && ranges[i].Contains(pn)
}
