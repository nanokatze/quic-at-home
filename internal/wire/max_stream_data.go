package wire

type MaxStreamData int64 // must be between 0 and MaxVarint incl.

func IsMaxStreamData(t byte) bool { return t == 0b10000100 }

func DecodeMaxStreamData(r *Reader) (MaxStreamData, error) {
	r.ReadByte()

	off, err := DecodeVarint(r)
	if err != nil {
		return MaxStreamData(0), err
	}

	return MaxStreamData(off), nil
}

func (off MaxStreamData) Encode(w *Writer) error {
	if err := w.WriteByte(0b10000100); err != nil {
		return err
	}
	if err := EncodeVarint(w, int64(off)); err != nil {
		return err
	}
	return nil
}
