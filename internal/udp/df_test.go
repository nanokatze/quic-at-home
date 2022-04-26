package udp

import (
	"net"
	"net/netip"
	"testing"
)

func TestSetDontFragment(t *testing.T) {
	uconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	pconn := &PacketConn{uconn}
	defer pconn.Close()

	t.Logf("local addr %v", pconn.LocalAddr())

	if err := pconn.setDontFragment(true); err != nil {
		t.Error(err)
	}

	for _, raddr := range []netip.AddrPort{
		netip.MustParseAddrPort("[::ffff:10.0.0.0]:10"),
	} {
		if _, err := pconn.WriteToUDPAddrPort(make([]byte, 100), raddr); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}

		_, err := pconn.WriteToUDPAddrPort(make([]byte, 10000), raddr)
		if err != nil {
			t.Logf("err = %v", err)
		} else {
			t.Fatalf("err = nil, want non-nil")
		}
	}
}
