package quic

import (
	"fmt"
	"math"
	"testing"

	"github.com/nanokatze/quic-at-home/internal/wire"
)

var guessPacketNumberTests = []struct {
	max       wire.PacketNumber
	truncated uint32
	correct   wire.PacketNumber
}{
	{math.MinInt64, 0, 0},
	{0, 0, 0},
	{0, 0x80000001, 0x80000001},
	{0, 0x80000002, 0x80000002},
	{0x100000000, 0x80000001, 0x180000001},
	{0x100000000, 0x80000002, 0x80000002},
	{0x123456709abcdee, 0x89abcdef, 0x123456789abcdef},
	{0x3ffffffffffffffe, 0xffffffff, 0x3fffffffffffffff},
	{0x3fffffffffffffff, 0xffffffff, 0x3fffffffffffffff},
}

func TestGuessPacketNumber(t *testing.T) {
	for i, test := range guessPacketNumberTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			guessed := guessPacketNumber(test.max, test.truncated)
			if guessed != test.correct {
				t.Errorf("guessed = 0x%x, want 0x%x", guessed, test.correct)
			}
		})
	}
}
