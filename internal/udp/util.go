package udp

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
