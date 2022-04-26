package wire

type Close struct{}

func IsClose(t byte) bool { return t == 0b11111111 }

func (Close) Encode(w *Writer) error {
	return w.WriteByte(0b11111111)
}
