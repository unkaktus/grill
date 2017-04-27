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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nogoegst/rand"
	"github.com/nogoegst/rough"
)

type ScanResult struct {
	addr   net.IP
	port   uint16
	err    error
	chacks uint32
	bursts []Burst
}

type Scanner struct {
	Addr       net.IP
	Port       uint16
	Routing    rough.Routing
	ProbeCount int
}

type Burst struct {
	ChACKs  int
	Elapsed time.Duration
}

func (scanner *Scanner) Scan(resultCh chan<- ScanResult) {
	s := &rough.TCP{}
	s.SetRouting(scanner.Routing)
	s.RemoteAddr = scanner.Addr
	s.LocalPort = rand.Uint16()
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

	result.bursts = make([]Burst, 2)
	ticker := time.NewTicker(time.Second)
	for b, _ := range result.bursts {
		go func() {
			for {
				tcp, ok := <-s.RX
				if !ok {
					break
				}
				if tcp.ACK {
					result.bursts[b].ChACKs += 1
				}
			}
		}()

		start := time.Now()
		for i := 0; i < scanner.ProbeCount; i++ {
			s.SendOut()
			s.WaitTX()
		}
		if time.Since(start) > 900*time.Millisecond {
			log.Fatalf("It took too long to send a burst. Get better connectivity")
		}
		result.bursts[b].Elapsed = time.Since(start)
		<-ticker.C
	}

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
		for r := range scanResults {
			if r.err == nil {
				fmt.Printf("%s:%d,%d,%s,%d,%s\n", r.addr, r.port, r.bursts[0].ChACKs, r.bursts[0].Elapsed, r.bursts[1].ChACKs, r.bursts[1].Elapsed)
			}
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
			}
			backoffms := rand.Intn(60*(simultScans-len(schScans)-1) + 1)
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
