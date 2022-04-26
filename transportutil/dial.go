package transportutil

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/nanokatze/quic-at-home"
)

const attempts = 5

// DialContext connects to the given address.
//
// If the address resolves to multiple IP addresses, DialContext will try to
// connect to all IP addresses concurrently.
func DialContext(ctx context.Context, mux *transport.Mux, address string, remoteStaticPublicKey transport.PublicKey) (*transport.Conn, error) {
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialResult struct {
		*transport.Conn
		error
	}
	results := make(chan dialResult)

	for _, ip := range ips {
		addr := netip.AddrPortFrom(ip, uint16(port))

		go func() {
			for i := 0; i < attempts; i++ {
				// See https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
				timeout := time.Duration(rand.Int63n(int64(time.Second << i)))

				dialCtx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()

				c, err := mux.DialContextAddrPort(dialCtx, remoteStaticPublicKey, addr)
				if err == transport.ErrAgain {
					c, err = mux.DialContextAddrPort(dialCtx, remoteStaticPublicKey, addr) // try again, with a new cookie
				}

				select {
				case results <- dialResult{Conn: c, error: err}:
					if c != nil {
						return
					}

				case <-ctx.Done():
					if c != nil {
						c.Close()
					}
					return
				}
			}
		}()
	}

	var firstErr error
loop:
	for i := 0; i < len(ips)*attempts; i++ {
		select {
		case res := <-results:
			if res.Conn != nil {
				return res.Conn, nil
			}
			if firstErr == nil {
				firstErr = res.error
			}

		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			break loop
		}
	}
	return nil, firstErr
}
