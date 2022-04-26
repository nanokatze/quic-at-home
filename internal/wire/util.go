package wire

import "io"

func DecodeLengthPrefixedBytes(r *Reader) ([]byte, error) {
	dataLen, err := DecodeVarint(r)
	if err != nil {
		return nil, err
	}
	if int64(int(dataLen)) != dataLen {
		return nil, io.ErrUnexpectedEOF
	}
	data := r.Next(int(dataLen))
	if len(data) != int(dataLen) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func EncodeLengthPrefixedBytes(w *Writer, p []byte) error {
	if err := EncodeVarint(w, int64(len(p))); err != nil {
		return err
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	return nil
}

// TODO: use standard generic Max when it appears in the Go standard library
func max[T ~int | ~int64](x, y T) T {
	if x > y {
		return x
	}
	return y
}

// TODO: use standard generic Min when it appears in the Go standard library
func min[T ~int | ~int64](x, y T) T {
	if x < y {
		return x
	}
	return y
}

// Equal reports whether two slices are equal: the same length and all
// elements equal. If the lengths are different, Equal returns false.
// Otherwise, the elements are compared in increasing index order, and the
// comparison stops at the first unequal pair.
// Floating point NaNs are not considered equal.
//
// TODO: replace with https://pkg.go.dev/golang.org/x/exp/slices#Equal if and
// when it is promoted to the Go standard library.
func slices_Equal[E comparable](s1, s2 []E) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}
