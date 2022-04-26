package wire

import "math"

const MaxPacketNumber = MaxVarint

type PacketNumber int64

type PacketNumberRange struct{ Min, Max PacketNumber }

func (r PacketNumberRange) Contains(pn PacketNumber) bool {
	return r.Min <= pn && pn <= r.Max
}

// PacketNumberRanges is a sorted slice of non-adjacent and disjoint packet
// number ranges.
type PacketNumberRanges []PacketNumberRange

func (ranges PacketNumberRanges) Max() PacketNumber {
	if len(ranges) == 0 {
		return math.MinInt64
	}
	return ranges[0].Max
}

func (ranges PacketNumberRanges) Contains(pn PacketNumber) bool {
	for _, r := range ranges {
		if r.Contains(pn) {
			return true
		}
	}
	return false
}

// TrimLesser returns a slice of ranges with ranges lesser than pn removed.
func (ranges PacketNumberRanges) TrimLesser(pn PacketNumber) PacketNumberRanges {
	for i, r := range ranges {
		if r.Max < pn {
			return ranges[:i]
		}
	}
	return ranges
}
