package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// Variable-length integer encoding is almost the same as QUIC's (see RFC9000,
// 16. Variable-Length Integer Encoding).

const MaxVarint = 1<<62 - 1

const noNonCanonical = false

func DecodeVarint(r *Reader) (int64, error) {
	b0 := r.PeekByte()
	l := 1 << (b0 & (1<<2 - 1))
	b := make([]byte, 8)
	if n, _ := r.Read(b[:l]); n != l {
		return 0, io.ErrUnexpectedEOF
	}
	y := int64(binary.LittleEndian.Uint64(b) >> 2)
	if noNonCanonical && VarintLen(y) != l {
		return 0, errors.New("non-canonical varint encoding")
	}
	return y, nil
}

func EncodeVarint(w *Writer, x int64) error {
	log2l := varintLog2Len(x)
	l := 1 << log2l
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(x)<<2|uint64(log2l))
	_, err := w.Write(b[:l])
	return err
}

func VarintLen(x int64) int {
	return 1 << varintLog2Len(x)
}

func varintLog2Len(x int64) int {
	switch {
	case x < 0:
		fallthrough
	default:
		panic("argument overflows varint")

	case x < 1<<6:
		return 0
	case x < 1<<14:
		return 1
	case x < 1<<30:
		return 2
	case x < 1<<62:
		return 3
	}
}
