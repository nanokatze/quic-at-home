package wire

import (
	"fmt"
	"strings"
	"testing"
)

var streamTests = []struct {
	off         int64
	dataLen     int
	n           int
	explicitLen bool // ignored if n = 0; must be set if dataLen < n-VarintLen(off)
	want        string
}{
	{10000000, 10, 0, false, ""},                                                // too little to fit
	{999, 999, 998, false, "\x82\x9d\x0f" + strings.Repeat("\x00", 998)},        // big blob at an offset that encodes to a two byte varint, with implicit length
	{999, 997, 996, true, "\x83\x9d\x0f\x91\x0f" + strings.Repeat("\x00", 996)}, // big blob at an offset that encodes to a two byte varint, with explicitLen
	{MaxVarint - 1, 1, 1, false, "\x82\xfb\xff\xff\xff\xff\xff\xff\xff\x00"},    // one byte at the end of stream with explicitLen
	{MaxVarint - 1, 1, 1, true, "\x83\xfb\xff\xff\xff\xff\xff\xff\xff\x04\x00"}, // one byte at the end of stream with implicit length
}

func TestStreamEncodeDecode(t *testing.T) {
	for i, test := range streamTests {
		if test.n == 0 {
			continue
		}

		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			buf := make([]byte, 10000)

			w := NewWriter(buf)
			if err := (&Stream{
				Off:  test.off,
				Data: make([]byte, test.n),
			}).Encode(w, test.explicitLen); err != nil {
				t.Fatalf("err = %v, want %v", err, error(nil))
			}

			buf = buf[:w.Len()]

			if string(buf) != test.want {
				t.Fatalf("buf = %x, want %x", buf, test.want)
			}

			r := NewReader(buf)
			s, err := DecodeStream(r)
			if err != nil {
				t.Fatalf("err = %v, want %v", err, error(nil))
			}
			if s.Off != test.off {
				t.Fatalf("s.Off = %d, want %d", s.Off, test.off)
			}
			if len(s.Data) != test.n {
				t.Fatalf("len(s.Data) = %d, want %d", len(s.Data), test.n)
			}
			if r.Remaining() != 0 {
				t.Fatalf("r.Remaining() = %d, want %d", r.Remaining(), 0)
			}
		})
	}
}

func TestMaxStreamDataLen(t *testing.T) {
	for i, test := range streamTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			n, explicitLen := StreamMaxDataLen(len(test.want), test.off, test.dataLen)
			if n != test.n {
				t.Errorf("n = %d, want %d", n, test.n)
			}
			if n > 0 && explicitLen != test.explicitLen {
				t.Errorf("explicitLen = %v, want %v", explicitLen, test.explicitLen)
			}
		})
	}
}
