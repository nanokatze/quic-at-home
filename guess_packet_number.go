package quic

import "github.com/nanokatze/quic-at-home/internal/wire"

func guessPacketNumber(maxPN wire.PacketNumber, truncatedPN uint32) wire.PacketNumber {
	if maxPN < 0 {
		maxPN = 0
	}
	pn := int64(truncatedPN) | (int64(maxPN) &^ 0xffffffff)
	if pn <= int64(maxPN)+1-0x80000000 && pn <= wire.MaxPacketNumber-0x100000000 {
		pn += 0x100000000
	} else if pn > int64(maxPN)+1+0x80000000 && pn >= 0x100000000 {
		pn -= 0x100000000
	}
	return wire.PacketNumber(pn)
}
