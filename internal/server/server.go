package server

import (
	"net"
	"log"
)

func Start(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Error listening:", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn)	//this will handle the connection concurrently
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	//log remote address
	log.Printf("New connection from %v", conn.RemoteAddr())
}



