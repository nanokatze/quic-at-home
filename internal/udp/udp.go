// https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html
package udp

import (
	"errors"
	"net"
	"net/netip"
)

type PacketConn struct {
	*net.UDPConn // TODO: hide methods?
}

func ListenAddrPort(laddr netip.AddrPort) (*PacketConn, error) {
	uconn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		return nil, err
	}
	pconn := &PacketConn{uconn}
	pconn.setGRO(true)
	pconn.setDontFragment(true)
	return pconn, nil
}

func (c *PacketConn) ReadFromUDPAddrPortGRO(b []byte) (int, int, netip.AddrPort, error) {
	return c.readFromUDPAddrPortGRO(b)
}

func (c *PacketConn) WriteToUDPAddrPortGSO(b []byte, ss int, raddr netip.AddrPort) (int, error) {
	if ss < 1200 || 65535 < ss {
		return 0, errors.New("bad segment size")
	}
	return c.writeToUDPAddrPortGSO(b, ss, raddr)
}
