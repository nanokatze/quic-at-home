package wire

import (
	"errors"
	"io"
)

type Stream struct {
	Off  int64  // 0 ≤ Off ≤ MaxVarint
	Data []byte // must be non-empty
}

func IsStream(t byte) bool { return t&^0b1 == 0b10000010 }

func DecodeStream(r *Reader) (Stream, error) {
	t, _ := r.ReadByte()

	off, err := DecodeVarint(r)
	if err != nil {
		return Stream{}, err
	}

	var dataLen int64
	if t&0b1 != 0 {
		var err error
		dataLen, err = DecodeVarint(r)
		if err != nil {
			return Stream{}, err
		}
		if int64(int(dataLen)) != dataLen {
			return Stream{}, io.ErrUnexpectedEOF
		}
	} else {
		dataLen = int64(r.Remaining())
	}
	if dataLen == 0 {
		return Stream{}, errors.New("empty STREAM")
	}
	if off+int64(dataLen) > MaxVarint {
		return Stream{}, errors.New("STREAM overflows offset")
	}

	data := r.Next(int(dataLen))
	if len(data) != int(dataLen) {
		return Stream{}, io.ErrUnexpectedEOF
	}

	return Stream{
		Off:  int64(off),
		Data: data,
	}, nil
}

func (s Stream) Encode(w *Writer, explicitLen bool) error {
	t := byte(0b10000010)
	if explicitLen {
		t |= 0b1
	}
	if err := w.WriteByte(t); err != nil {
		return err
	}
	if err := EncodeVarint(w, s.Off); err != nil {
		return err
	}
	if explicitLen {
		if err := EncodeVarint(w, int64(len(s.Data))); err != nil {
			return err
		}
	}
	_, err := w.Write(s.Data)
	return err
}

// n, off and dataLen must be non-negative.
func StreamMaxDataLen(n int, off int64, dataLen int) (int, bool) {
	overhead := 1 + VarintLen(off)
	if n < overhead+1 {
		// Too small to fit the offset and a single byte of data.
		return 0, false
	}

	if n <= overhead+dataLen {
		// The data is at least n-1-VarintLen(off) big. Don't write the
		// length.
		return n - overhead, false
	}

	// min(n-overhead-1, dataLen) is a conservative bound on length of data
	// that can be written. The length can not be greater than the data, or
	// size of the remainder of the buffer, minus at least one byte for
	// the length itself.
	return min(n-overhead-VarintLen(int64(min(n-overhead-1, dataLen))), dataLen), true
}
