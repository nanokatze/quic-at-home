package wire

import (
	"fmt"
	"math"
	"reflect"
	"testing"
)

// TODO: STREAM and MSG tests. These frames are tricky to test, because in
// certain cases, when non-canonically encoded, they can be larger than when
// encoded canonically.

var fuzzTests = []func(*testing.T, []byte){
	func(t *testing.T, data []byte) {
		fuzzHelper(t, data, func(r *Reader) (Ack, error) { return DecodeAck(r, math.MaxInt) })
	},
	func(t *testing.T, data []byte) { fuzzHelper(t, data, DecodePing) },
	func(t *testing.T, data []byte) { fuzzHelper(t, data, DecodeMaxStreamData) },
}

func Fuzz(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		for i, f := range fuzzTests {
			t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
				f(t, data)
			})
		}
	})
}

func fuzzHelper[T interface{ Encode(*Writer) error }](t *testing.T, data []byte, Decode func(*Reader) (T, error)) {
	x, err := Decode(NewReader(data))
	if err != nil {
		return
	}

	buf := make([]byte, len(data))
	if err := x.Encode(NewWriter(buf)); err != nil {
		t.Fatal(err)
	}

	y, err := Decode(NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(x, y) {
		t.Fatalf("x = %#v, y = %#v", x, y)
	}
}
