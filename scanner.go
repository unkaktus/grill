// scanner.go - scan for CVE-2016-5696
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of grill, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	badrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nogoegst/rough"
)

type ScanResult struct {
	addr    net.IP
	port    uint16
	err     error
	chacks  uint32
	elapsed time.Duration
}

func Scan(resultCh chan<- ScanResult, routing rough.Routing, addr net.IP, port uint16) {
	s := &rough.TCP{}
	s.SetRouting(routing)
	s.RemoteAddr = addr
	s.LocalPort = rough.RandUint16()
	s.RemotePort = port
	s.Open()
	defer s.Close()

	result := ScanResult{addr: addr, port: port}

	hsResult := make(chan bool)
	go s.DoHandshake(hsResult)
	if r := <-hsResult; !r {
		result.err = fmt.Errorf("Handshake has failed")
		resultCh <- result
		return
	}

	inWinOffset := uint32(101) // lol
	s.Pkt.Window = 2048
	s.Pkt.RST = true
	s.Pkt.Seq = s.Pkt.Seq + inWinOffset

	var rxWg sync.WaitGroup
	rxWg.Add(1)
	go func() {
		t := time.After(7 * time.Second)
	L:
		for {
			select {
			case <-t:
				break L
			case tcp := <-s.RX:
				if tcp.ACK {
					result.chacks += 1
				}
			}
		}
		rxWg.Done()
	}()

	probesNumber := 500

	start := time.Now()
	for i := 0; i < probesNumber; i++ {
		s.SendOut()
		s.WaitTX()
	}
	result.elapsed = time.Since(start)
	rxWg.Wait()
	//Send right RST
	s.Pkt.Seq -= inWinOffset
	s.SendOut()
	s.WaitTX()
	resultCh <- result
	return

}
func main() {
	routing := rough.Routing{}
	var device = flag.String("i", "", "Interface for packet injection")
	var srcLLAddr = flag.String("sll", "", "Source link-layer address")
	var dstLLAddr = flag.String("dll", "", "Destination link-layer address")
	var srcIPAddr = flag.String("sip", "", "Source IP address")
	flag.Parse()

	routing.Device = *device
	log.Printf("%v", *device)
	routing.SrcLLAddr, _ = net.ParseMAC(*srcLLAddr)
	routing.DstLLAddr, _ = net.ParseMAC(*dstLLAddr)
	routing.SrcIPAddr = net.ParseIP(*srcIPAddr)

	simultScans := 16
	schScans := make(chan struct{}, simultScans)
	scanResults := make(chan ScanResult, simultScans)
	for i := 0; i < simultScans; i++ {
		schScans <- struct{}{}
	}

	finished := make(chan struct{})
	go func() {
		for result := range scanResults {
			fmt.Printf("%s:%d,%d,%s\n", result.addr, result.port, result.chacks, result.elapsed)
			schScans <- struct{}{}
		}
		finished <- struct{}{}
	}()

	var wg sync.WaitGroup
	reader := bufio.NewReader(os.Stdin)
	i := 0
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		if err != nil {
			break
		}

		<-schScans

		i += 1
		log.Printf("[%d] Initiating scan for %s", i, line)
		lineSplit := strings.SplitN(line, " ", 2)
		addr := net.ParseIP(lineSplit[0])
		portu64, err := strconv.ParseUint(lineSplit[1], 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		port := uint16(portu64)
		wg.Add(1)
		go func() {
			time.Sleep(time.Duration(badrand.Intn(6000)) * time.Millisecond)
			Scan(scanResults, routing, addr, port)
			wg.Done()
		}()
	}
	wg.Wait()
	close(scanResults)
	<-finished
	log.Printf("Done scanning")

}
