//go:build ignore

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/netip"
	"os"
	"runtime/pprof"
	"time"

	"github.com/nanokatze/quic-at-home"
	"github.com/nanokatze/quic-at-home/transportutil"
)

var address = "127.0.0.1:32017"

func makeTestdata() []byte {
	plentyofroom, _ := os.ReadFile("testdata/plentyofroom")

	var testdata []byte
	for i := 0; i < 1000; i++ {
		testdata = append(testdata, plentyofroom...)
	}
	return testdata
}

var testdata = makeTestdata()

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	switch len(os.Args) {
	case 1:
	case 2:
		address = os.Args[1]
	default:
		fmt.Fprintf(os.Stderr, "usage: go run echo-client.go [address]\n")
		os.Exit(1)
	}

	{
		f, err := os.Create("echo-client.cpu.prof")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	ln, err := quic.ListenAddrPort(netip.AddrPort{}, &quic.Config{
		StreamReceiveWindow:    1000000,
		MaxStreamBytesInFlight: 1000000,
		PrivateKey:             clientPrivKey,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Print("muxing on ", ln.LocalAddrPort())

	c, err := transportutil.DialContext(context.Background(), ln, address, serverPubKey)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	t0 := time.Now()

	switch "stream" {
	case "stream":
		done := make(chan struct{})
		go func() {
			defer close(done)

			buf := make([]byte, len(testdata))
			for n := 0; n < len(buf); {
				nn, err := c.Read(buf[n:])
				if err != nil {
					log.Fatal(err)
				}
				n += nn

				// log.Print(n, " out of ", len(testdata), " bytes round-tripped")
			}
			if !bytes.Equal(buf, testdata) {
				log.Fatal("fail")
			}
		}()

		for i := 0; i < len(testdata); i += 10000 {
			b := testdata[i:]
			if len(b) > 10000 {
				b = b[:10000]
			}
			if _, err := c.Write(b); err != nil {
				log.Fatal(err)
			}

			if rand.Intn(100) == 0 {
				// time.Sleep(100 * time.Millisecond)
			}
		}

		<-done

	case "msg":
		c.SetMsgReceiveWindow(100000)

		done := make(chan struct{})
		go func() {
			defer close(done)

			buf := make([]byte, len(testdata))
			if _, err := c.ReadMsg(buf); err != nil {
				log.Fatal(err)
			}
			if !bytes.Equal(buf, testdata) {
				log.Fatal("fail")
			}
		}()

		const N = 100
	Loop:
		for i := 0; i < N; i++ {
			log.Printf("%d...", i)

			if _, err := c.WriteMsg(testdata); err != nil {
				log.Fatal(err)
			}

			select {
			case <-done:
				log.Print("ok")
				break Loop
			case <-time.After(time.Second / 10):
			}

			if i == N-1 {
				log.Fatal("fail")
			}
		}
	}

	t := time.Since(t0)

	log.Print("took ", t, " at ", (float64(len(testdata))/1024)/(float64(t)/1e9), " KiB per second")
}

var clientPrivKey, _ = hex.DecodeString("f9818a3ef5bb4f93630ad471930946ae809be878d08e01014eedbb61f4689301")
var serverPubKey, _ = hex.DecodeString("b8b4536dbf14d47732fa7db07fbdaea7b0f61f7aa9f7310fc4d47098bc048a2d") // keep in sync with echo-srv.go:serverPrivKey
