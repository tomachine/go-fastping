package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/kanocz/go-fastping"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <IP> <count>\n", os.Args[0])
		return
	}

	count, err := strconv.ParseUint(os.Args[2], 10, 64)
	if nil != err {
		log.Fatalln("Error parsing count:", err)
	}

	p := fastping.NewPinger()
	err = p.AddIP(os.Args[1])
	if nil != err {
		log.Fatalln("Error adding ip:", err)
	}

	p.MaxRTT = time.Second

	totalCount := 0
	rttSumm := time.Duration(0)
	rttMin := time.Duration(0)
	rttMax := time.Duration(0)

	for i := uint64(0); i < count; i++ {
		result, err := p.Run(map[string]bool{})
		if err != nil {
			log.Fatalln("Pinger error:", err)
		}
		fmt.Printf("%v ", result[os.Args[1]])
		if result[os.Args[1]] > 0 {
			totalCount++
			rttSumm += result[os.Args[1]]
			if (rttMin == 0) || (rttMin > result[os.Args[1]]) {
				rttMin = result[os.Args[1]]
			}
			if rttMax < result[os.Args[1]] {
				rttMax = result[os.Args[1]]
			}
		}
	}
	fmt.Println(" done!")
	fmt.Printf("Pings received %d/%d with rtt = %v/%v/%v\n", totalCount, count,
		rttMin, rttSumm/time.Duration(totalCount), rttMax)
}
