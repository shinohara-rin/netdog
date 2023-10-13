package netdog

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

type NetDog struct {
	verbose bool
}

func New() (*NetDog, error) {
	return &NetDog{}, nil
}

func (dog *NetDog) ConnectToPeer(hostname string, port uint16) {
	server := net.JoinHostPort(hostname, strconv.Itoa(int(port)))
	tcpAddr, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.Write([]byte("Ping"))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(buf))
}

func (dog *NetDog) WaitForPeer(port uint16) {
	listen := fmt.Sprintf(":%d", port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		panic(err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			panic(err)
		}
		go dog.HandlePeerConnection(conn)
	}
}

func (dog *NetDog) HandlePeerConnection(conn *net.TCPConn) {
	defer conn.Close()
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	if err != nil {
		log.Fatalln(conn.RemoteAddr(), err)
		return
	}

	fmt.Println(string(buf))
	conn.Write([]byte("Pong"))
}

func (dog *NetDog) v(msg string) {
	if dog.verbose {
		fmt.Println(msg)
	}
}
