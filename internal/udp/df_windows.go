// https://github.com/lucas-clemente/quic-go/blob/3126062aa7ba5e572adc1888ba4480fd78b3a1fe/sys_conn_df_windows.go
//
// Copyright (c) 2016 the quic-go authors & Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package udp

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

const (
	windows_IP_DONTFRAGMENT = 0xe
	windows_IPV6_DONTFRAG   = 0xe
)

var ErrMessageTooLong = unix.EMSGSIZE

func (c *PacketConn) setDontFragment(df bool) error {
	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var err4, err6 error
	if err := sc.Control(func(fd uintptr) {
		err4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows_IP_DONTFRAGMENT, 1)
		err6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows_IPV6_DONTFRAG, 1)
	}); err != nil {
		return err
	}
	if err4 != nil || err6 != nil {
		return &setDontFragmentError{err4, err6}
	}
	return nil
}
