//go:build !linux && !windows

package transport

import (
	"errors"
	"net"
)

var ErrMessageTooLong = errors.New("message too long")

func (c *PacketConn) setDontFragment(df bool) error {
	return errors.New("not implemented")
}
