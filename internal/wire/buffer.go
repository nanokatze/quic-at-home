package wire

import "io"

type Reader struct {
	buf []byte
}

func NewReader(buf []byte) *Reader { return &Reader{buf: buf} }

func (r *Reader) PeekByte() byte {
	if len(r.buf) == 0 {
		return 0
	}
	return r.buf[0]
}

func (r *Reader) ReadByte() (byte, error) {
	buf := make([]byte, 1)
	_, err := r.Read(buf)
	return buf[0], err
}

func (r *Reader) Read(p []byte) (int, error) {
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (r *Reader) Next(n int) []byte {
	if n > len(r.buf) {
		n = len(r.buf)
	}
	s := r.buf[:n]
	r.buf = r.buf[n:]
	return s
}

func (r *Reader) Remaining() int { return len(r.buf) }

type Writer struct {
	buf []byte
}

func NewWriter(buf []byte) *Writer { return &Writer{buf: buf[0:0:len(buf)]} }

func (w *Writer) WriteByte(c byte) error {
	_, err := w.Write([]byte{c})
	return err
}

func (w *Writer) Write(p []byte) (int, error) {
	l := len(w.buf)
	c := cap(w.buf)
	n := copy(w.buf[l:c], p)
	w.buf = w.buf[0 : l+n]
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (w *Writer) Len() int { return len(w.buf) }

func (w *Writer) Remaining() int { return cap(w.buf) - len(w.buf) }
