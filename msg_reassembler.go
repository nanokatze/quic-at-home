package quic

import "io"

type msgReassembler struct {
	rb, wb []byte
}

func newMsgReassembler(n int) *msgReassembler {
	return &msgReassembler{
		rb: make([]byte, 0, n),
		wb: make([]byte, 0, n),
	}
}

func (a *msgReassembler) Read(p []byte) (int, error) {
	n := copy(p, a.rb)
	a.rb = a.rb[:0]
	return n, nil
}

func (a *msgReassembler) Clear() {
	a.wb = a.wb[:0]
}

func (a *msgReassembler) Write(p []byte) (int, error) {
	l := len(a.wb)
	c := cap(a.wb)
	n := copy(a.wb[l:c], p)
	a.wb = a.wb[:l+n]
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (a *msgReassembler) Swap() {
	a.rb, a.wb = a.wb, a.rb[:0]
}
