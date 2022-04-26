package quic

import (
	"fmt"
	"strings"
	"testing"
)

type streamReassemblerTest interface {
	Do(*streamReassembler) error
}

type streamReassemblerAssert struct {
	wantCanBeRead bool
	wantMaxOffset int64
}

func (s streamReassemblerAssert) Do(as *streamReassembler) error {
	if as.CanBeRead() != s.wantCanBeRead {
		return fmt.Errorf("as.CanBeRead() = %v, want %v", as.CanBeRead(), s.wantCanBeRead)
	}
	if as.MaxOffset() != s.wantMaxOffset {
		return fmt.Errorf("as.MaxOffset() = %v, want %v", as.MaxOffset(), s.wantMaxOffset)
	}
	return nil
}

type streamReassemblerRead struct {
	n    int
	want string
}

func (s streamReassemblerRead) Do(as *streamReassembler) error {
	buf := make([]byte, s.n)
	n, err := as.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != s.want {
		return fmt.Errorf("buf[:n] = %q, want %q", buf[:n], s.want)
	}
	return nil
}

type streamReassemblerWrite struct {
	buf     string
	off     int64
	wantErr bool
}

func (s streamReassemblerWrite) Do(as *streamReassembler) error {
	_, err := as.WriteAt([]byte(s.buf), s.off)
	if (err != nil) != s.wantErr {
		return fmt.Errorf("err = %v", err)
	}
	return nil
}

var streamReassemblerTests = []struct {
	window int
	tests  []streamReassemblerTest
}{
	{
		window: 10,
		tests: []streamReassemblerTest{
			streamReassemblerWrite{"Test data", 0, false},
			streamReassemblerRead{999, "Test data"},
			streamReassemblerAssert{false, 19},
		},
	},
	{
		window: 10,
		tests: []streamReassemblerTest{
			streamReassemblerWrite{" data", 4, false},
			streamReassemblerRead{999, ""},
			streamReassemblerWrite{"Test", 0, false},
			streamReassemblerRead{999, "Test data"},
			streamReassemblerAssert{false, 19},
		},
	},
	{
		window: 10,
		tests: []streamReassemblerTest{
			streamReassemblerWrite{"?????????", 0, false}, // pad
			streamReassemblerRead{999, "?????????"},
			streamReassemblerWrite{"Test", 9, false},
			streamReassemblerRead{999, "T"}, // wraparound
			streamReassemblerRead{999, "est"},
			streamReassemblerAssert{false, 23},
		},
	},
	{
		window: 64,
		tests: []streamReassemblerTest{
			streamReassemblerWrite{strings.Repeat(".", 32), 0, false},
			streamReassemblerWrite{strings.Repeat(".", 32), 32, false},
			streamReassemblerWrite{".", 64, true},
			streamReassemblerRead{999, strings.Repeat(".", 64)},
			streamReassemblerAssert{false, 128},
		},
	},
}

func TestStreamReassembler(t *testing.T) {
	for i, sub := range streamReassemblerTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			as := newStreamReassembler(sub.window)

			for j, test := range sub.tests {
				err := test.Do(as)
				if err != nil {
					t.Fatalf("%d: %v", j, err)
				}
			}
		})
	}
}
