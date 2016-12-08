// verdict.go - append vulnerabilty status to each line of grill results.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of grill, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	var f *os.File
	if len(os.Args) == 1 {
		f = os.Stdin
	} else {
		f, err := os.Open(os.Args[1])
		if err != nil {
			log.Fatalf("Unable to open file: %v", err)
		}
		defer f.Close()
	}
	r := csv.NewReader(f)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		var verdict string
		if rec[2] == "0s" {
			verdict = "offline"
		} else {
			chacks, _ := strconv.Atoi(rec[1])
			switch chacks {
			case 100, 200, 300, 400:
				verdict = "vulnerable"
			case 98, 99:
				verdict = "likely vulnerable"
			case 500:
				verdict = "sysctl workaround/fixed kernel"
			case 498, 499:
				verdict = "likely sysctl workaround/fixed kernel"
			case 0:
				verdict = "zero challenge ACKs"
			case 1:
				verdict = "one challenge ACK"
			case 391:
				verdict = "391G/sysctl workaround on a fixed kernel?"
			default:
				verdict = "many challenge ACKs"
			}
		}
		//h := strings.SplitN(rec[0], ":", 2)
		//fmt.Printf("%s:%s\n", h[0], h[1])
		fmt.Printf("%s,%s\n", strings.Join(rec, ","), verdict)
	}
}
