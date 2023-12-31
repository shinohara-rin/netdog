package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/shinohara-rin/netdog/internal/netdog"
)

func getPort(portstr string) uint16 {
	parsedP, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		fmt.Print("invalid port number")
	}
	return uint16(parsedP)
}

func main() {
	var (
		listen   bool
		verbose  bool
		hostname string
		port     uint16
	)

	flag.BoolVar(&listen, "l", false, "listen")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Parse()

	dog, err := netdog.New(verbose)
	if err != nil {
		log.Fatalln(err)
		os.Exit(-1)
	}

	if listen {
		port = getPort(flag.Arg(0))
		dog.WaitForPeer(port)
	} else {
		hostname = flag.Arg(0)
		port = getPort(flag.Arg(1))
		err := dog.ConnectToPeer(hostname, port)
		if err != nil {
			fmt.Println(err)
		}
		args := flag.Args()
		if len(args) < 3 {
			err = dog.TransferStdin()
		} else {
			err = dog.TransferFile(args[2:])
		}
		if err != nil {
			fmt.Println(err)
		}
	}
}
