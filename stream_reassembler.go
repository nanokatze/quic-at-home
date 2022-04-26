package quic

import "errors"

type streamReassembler struct {
	readable bitset
	buf      []byte
	off      int64
}

func newStreamReassembler(n int) *streamReassembler {
	return &streamReassembler{
		readable: newBitset(n),
		buf:      make([]byte, n),
		off:      0,
	}
}

func (a *streamReassembler) Read(b []byte) (int, error) {
	i := int(a.off % int64(len(a.buf)))
	n := a.readable.ClearRun(i, min(i+len(b), len(a.buf)))
	copy(b[:n], a.buf[i:])
	a.off += int64(n)
	return n, nil
}

func (a *streamReassembler) WriteAt(b []byte, off int64) (int, error) {
	n := 0
	if off < a.off {
		if off+int64(len(b)) < a.off {
			return len(b), nil
		}
		n = int(a.off - off)
		b = b[n:]
		off = a.off
	}
	if off+int64(len(b)) > a.off+int64(len(a.buf)) {
		return 0, errors.New("reassembler overflow")
	}
	i := int(off % int64(len(a.buf)))
	j := min(i+len(b), len(a.buf))
	a.readable.Set(i, j)
	nn := copy(a.buf[i:j], b[0:])
	n += nn
	a.readable.Set(0, len(b)-nn)
	n += copy(a.buf[0:], b[nn:])
	return n, nil
}

func (a *streamReassembler) MaxOffset() int64 {
	return a.off + int64(len(a.buf))
}

func (a *streamReassembler) CanBeRead() bool {
	return a.readable.Test(int(a.off % int64(len(a.buf))))
}
