package quic

import (
	"sync"
	"time"
)

const forever = 1000000 * time.Second

// TODO: use standard generic Max and Min when they appear in the Go standard library

func max[T ~int | ~int64](x, y T) T {
	if x > y {
		return x
	}
	return y
}

func min[T ~int | ~int64](x, y T) T {
	if x < y {
		return x
	}
	return y
}

// slices_Clone returns a copy of the slice.
// The elements are copied using assignment, so this is a shallow clone.
//
// TODO: replace with https://pkg.go.dev/golang.org/x/exp/slices#Clone if and
// when it is promoted to the Go standard library. Note that we have some
// old-style instances of slices.Clone i.e. append([]T(nil), s...) in internal
// subpackages.
func slices_Clone[S ~[]E, E any](s S) S {
	// Preserve nil in case it matters.
	if s == nil {
		return nil
	}
	return append(S([]E{}), s...)
}

// TODO: replace with the standard generic sync.Map when it is added to the Go
// standard library.
type syncMap[K comparable, E any] sync.Map

func (m *syncMap[K, E]) Load(key K) (value E, ok bool) {
	var zero E
	elem, ok := (*sync.Map)(m).Load(key)
	if ok {
		return elem.(E), true
	}
	return zero, false
}

func (m *syncMap[K, E]) Store(key K, value E) {
	(*sync.Map)(m).Store(key, value)
}

func (m *syncMap[K, E]) LoadOrStore(key K, value E) (actual E, loaded bool) {
	old, loaded := (*sync.Map)(m).LoadOrStore(key, value)
	return old.(E), loaded
}

func (m *syncMap[K, E]) Delete(key K) {
	(*sync.Map)(m).Delete(key)
}
