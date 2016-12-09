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
	addr     net.IP
	port     uint16
	err      error
	chacks   uint32
	elapsed1 time.Duration
	elapsed2 time.Duration
}

type Scanner struct {
	Addr       net.IP
	Port       uint16
	Routing    rough.Routing
	ProbeCount int
	Timeout    time.Duration
}

func (scanner *Scanner) Scan(resultCh chan<- ScanResult) {
	s := &rough.TCP{}
	s.SetRouting(scanner.Routing)
	s.RemoteAddr = scanner.Addr
	s.LocalPort = rough.RandUint16()
	s.RemotePort = scanner.Port
	s.Open()
	defer s.Close()

	result := ScanResult{addr: scanner.Addr, port: scanner.Port}

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
		t := time.After(scanner.Timeout)
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

	ticker := time.NewTicker(time.Second)
	// Send first burst
	start := time.Now()
	for i := 0; i < scanner.ProbeCount; i++ {
		s.SendOut()
		s.WaitTX()
	}
	result.elapsed1 = time.Since(start)

	// Send second burst
	<-ticker.C
	start = time.Now()
	for i := 0; i < scanner.ProbeCount; i++ {
		s.SendOut()
		s.WaitTX()
	}
	result.elapsed2 = time.Since(start)
	rxWg.Wait()
	ticker.Stop()
	//Send a valid RST
	s.Pkt.Seq -= inWinOffset
	s.SendOut()
	s.WaitTX()
	resultCh <- result
	return

}
func main() {
	routing := rough.Routing{}
	var probeCount = flag.Int("probes", 111, "Number of probe packets in one burst")
	var simultScanFlag = flag.Int("n", 16, "Number simultaneous scans")
	var device = flag.String("i", "", "Interface for packet injection")
	var srcLLAddr = flag.String("sll", "", "Source link-layer address")
	var dstLLAddr = flag.String("dll", "", "Destination link-layer address")
	var srcIPAddr = flag.String("sip", "", "Source IP address")
	flag.Parse()

	if *device == "" {
		log.Fatalf("Please specify interface")
	}
	iface, err := net.InterfaceByName(*device)
	if err != nil {
		log.Fatal(err)
	}
	routing.Device = *device
	if *srcLLAddr == "" {
		routing.SrcLLAddr = iface.HardwareAddr
	} else {
		routing.SrcLLAddr, err = net.ParseMAC(*srcLLAddr)
		if err != nil {
			log.Fatalf("Invalid source MAC address")
		}
	}
	routing.DstLLAddr, err = net.ParseMAC(*dstLLAddr)
	if err != nil {
		log.Fatalf("Invalid destination MAC address")
	}
	if *srcIPAddr == "" {
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			log.Fatalf("Unable to get IP address of interface: %v", err)
		}
		if addrs[0].Network() != "ip+net" {
			log.Fatalf("Interface address is not supported")
		}
		routing.SrcIPAddr, _, _ = net.ParseCIDR(addrs[0].String())
	} else {
		routing.SrcIPAddr = net.ParseIP(*srcIPAddr)
	}

	simultScans := *simultScanFlag
	schScans := make(chan struct{}, simultScans)
	scanResults := make(chan ScanResult, simultScans)
	for i := 0; i < simultScans; i++ {
		schScans <- struct{}{}
	}

	finished := make(chan struct{})
	go func() {
		for result := range scanResults {
			fmt.Printf("%s:%d,%d,%s,%s\n", result.addr, result.port, result.chacks, result.elapsed1, result.elapsed2)
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
		if len(lineSplit) != 2 {
			log.Fatalf("Broken input")
		}
		addr := net.ParseIP(lineSplit[0])
		portu64, err := strconv.ParseUint(lineSplit[1], 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		port := uint16(portu64)
		wg.Add(1)
		go func() {
			scanner := Scanner{
				Addr:       addr,
				Port:       port,
				Routing:    routing,
				ProbeCount: *probeCount,
				// This can be 1700, seems to work.
				Timeout:    3000 * time.Millisecond,
			}
			backoffms := badrand.Intn(60*(simultScans-len(schScans)-1) + 1)
			time.Sleep(time.Duration(backoffms) * time.Millisecond)
			scanner.Scan(scanResults)
			wg.Done()
		}()
	}
	wg.Wait()
	close(scanResults)
	<-finished
	log.Printf("Done scanning")

}
