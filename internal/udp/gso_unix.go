package udp

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	unix_SOL_UDP = 0x11

	unix_UDP_SEGMENT = 0x67
	unix_UDP_GRO     = 0x68
)

func (c *PacketConn) readFromUDPAddrPortGRO(b []byte) (int, int, netip.AddrPort, error) {
	oob := make([]byte, 24)
	n, oobn, flags, raddr, err := c.ReadMsgUDPAddrPort(b, oob)
	if flags&unix.MSG_CTRUNC != 0 {
		panic("oob buffer too small")
	}
	ss := n
	// TOOD: don't use ParseSocketControlMessage as this allocs and causes
	// oob to leak to heap as well
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		panic(err) // should not happen
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix_SOL_UDP && m.Header.Type == unix_UDP_GRO:
			ss = int(*(*uint16)(unsafe.Pointer(&m.Data[0])))
		}
	}
	return n, ss, raddr, err
}

func (c *PacketConn) writeToUDPAddrPortGSO(b []byte, ss int, raddr netip.AddrPort) (int, error) {
	// TODO: solve this allocing
	oob := unix_SegmentSize(uint16(ss))

	segs := max(60000/ss, 1) // TODO: pick a better constant

	n := 0
	for n < len(b) {
		nn, _, err := c.WriteMsgUDPAddrPort(b[n:n+min(segs*ss, len(b)-n)], oob, raddr)
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *PacketConn) setGRO(gro bool) error {
	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var soerr error
	if err := sc.Control(func(fd uintptr) {
		soerr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix_UDP_GRO, 1)
	}); err != nil {
		return err
	}
	if soerr != nil {
		return soerr
	}
	return nil
}

func unix_SegmentSize(ss uint16) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix_SOL_UDP
	h.Type = unix_UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	*(*uint16)(unix_Cmsghdr_data(h, 0)) = ss
	return b
}

/*
func unix_ParseSegmentSize(b []byte) (int, error) {
}
*/

func unix_Cmsghdr_data(h *unix.Cmsghdr, offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(unix.CmsgLen(0)) + offset)
}
