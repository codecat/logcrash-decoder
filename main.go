package main

import (
	"flag"

	"github.com/codecat/go-libs/log"
)

func main() {
	flag.Parse()
	for _, p := range flag.Args() {
		err := transformLog(p)
		if err != nil {
			log.Error("Unable to decode %s: %s", p, err.Error())
		}
	}
}
