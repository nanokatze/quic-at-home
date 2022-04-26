package quic

// TODO: maybe convert to use uint
type bitset []uint32

func newBitset(n int) bitset { return bitset(make([]uint32, (n+32-1)/32)) }

// Test returns whether bit i is set.
func (bs bitset) Test(i int) bool {
	return bs[i/32]&(1<<(i%32)) != 0
}

// Set sets bits i through j-1.
func (bs bitset) Set(i, j int) {
	_, _ = bs[i/32], bs[(j-1)/32]

	for ; i < j && i%32 != 0; i++ {
		bs[i/32] |= 1 << (i % 32)
	}
	for ; i+32 <= j; i += 32 {
		bs[i/32] = 0xffffffff
	}
	for ; i < j; i++ {
		bs[i/32] |= 1 << (i % 32)
	}
}

// ClearRun clear bits i through k-1 or until a cleared bit is found.
func (bs bitset) ClearRun(i, k int) int {
	_, _ = bs[i/32], bs[(k-1)/32]

	j := i
	for ; j < k && bs[j/32]&(1<<(j%32)) != 0 && j%32 != 0; j++ {
		bs[j/32] &^= 1 << (j % 32)
	}
	for ; j+32 <= k && bs[j/32] == 0xffffffff; j += 32 {
		bs[j/32] = 0
	}
	for ; j < k && bs[j/32]&(1<<(j%32)) != 0; j++ {
		bs[j/32] &^= 1 << (j % 32)
	}
	return j - i
}
