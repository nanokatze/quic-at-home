//go:build ignore

package main

import (
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"github.com/nanokatze/quic-at-home"
)

var laddr = netip.MustParseAddrPort("[::]:32017")

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	{
		f, err := os.Create("echo-srv.cpu.prof")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	ln, err := quic.ListenAddrPort(laddr, &quic.Config{
		StreamReceiveWindow:    1000000,
		MaxStreamBytesInFlight: 1000000,
		PrivateKey:             serverPrivKey,
		Listen:                 true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		defer ln.Close()
		<-c
	}()

	log.Print("muxing on ", ln.LocalAddrPort())

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			break
		}

		log.Printf("accepted %p", c)

		go handle(c)
		go handle2(c)
	}
}

func handle(c *quic.Conn) {
	defer c.Close()

	buf := make([]byte, 1000000)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				return
			}
			log.Print(err)
			return
		}
		if _, err := c.Write(buf[:n]); err != nil {
			log.Print(err)
			return
		}
	}
}

func handle2(c *quic.Conn) {
	defer c.Close()

	c.SetMsgReceiveWindow(1000000)

	buf := make([]byte, 1000000)
	for {
		n, err := c.ReadMsg(buf)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				return
			}
			log.Print(err)
			return
		}
		if _, err := c.WriteMsg(buf[:n]); err != nil {
			log.Print(err)
			return
		}
	}
}

var serverPrivKey, _ = hex.DecodeString("7aec9ec1610fbe44be412a81c7076e518684244988db9a1e1f27d58445444a57")
