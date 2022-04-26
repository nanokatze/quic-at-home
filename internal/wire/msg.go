package wire

import (
	"errors"
	"io"
)

type Msg struct {
	First bool
	Last  bool
	Seq   int64  // 0 ≤ Seq ≤ MaxVarint
	Data  []byte // must be non-empty
}

func IsMsg(t byte) bool { return t&^0b111 == 0b10001000 }

func DecodeMsg(r *Reader) (Msg, error) {
	t, _ := r.ReadByte()

	seq, err := DecodeVarint(r)
	if err != nil {
		return Msg{}, err
	}

	var dataLen int64
	if t&0b001 != 0 {
		var err error
		dataLen, err = DecodeVarint(r)
		if err != nil {
			return Msg{}, err
		}
		if int64(int(dataLen)) != dataLen {
			return Msg{}, io.ErrUnexpectedEOF
		}
	} else {
		dataLen = int64(r.Remaining())
	}
	if dataLen == 0 {
		return Msg{}, errors.New("empty MSG")
	}

	data := r.Next(int(dataLen))
	if len(data) != int(dataLen) {
		return Msg{}, io.ErrUnexpectedEOF
	}

	return Msg{
		First: t&0b010 != 0,
		Last:  t&0b100 != 0,
		Seq:   int64(seq),
		Data:  data,
	}, nil
}

func (m Msg) Encode(w *Writer, explicitLen bool) error {
	t := byte(0b10001000)
	if explicitLen {
		t |= 0b001
	}
	if m.First {
		t |= 0b010
	}
	if m.Last {
		t |= 0b100
	}
	if err := w.WriteByte(t); err != nil {
		return err
	}
	if err := EncodeVarint(w, m.Seq); err != nil {
		return err
	}
	if explicitLen {
		if err := EncodeVarint(w, int64(len(m.Data))); err != nil {
			return err
		}
	}
	_, err := w.Write(m.Data)
	return err
}

// See StreamMaxDataLen.
func MsgMaxDataLen(n int, seq int64, dataLen int) (int, bool) {
	overhead := 1 + VarintLen(seq)
	if n < overhead+1 {
		return 0, false
	}
	if n <= overhead+dataLen {
		return n - overhead, false
	}
	return min(n-overhead-VarintLen(int64(min(n-overhead-1, dataLen))), dataLen), true
}
