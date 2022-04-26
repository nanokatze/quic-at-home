package wire

type Ping struct{}

func IsPing(t byte) bool { return t == 0b00000001 }

func DecodePing(r *Reader) (Ping, error) {
	_, err := r.ReadByte()
	return Ping{}, err
}

func (Ping) Encode(w *Writer) error {
	return w.WriteByte(0b00000001)
}
