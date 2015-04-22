package quic

import (
	"log"
	"net"
)

// Listener represents a QUIC connection
type Listener struct {
	udp *net.UDPConn
}

// Close closes the QUIC Listener
func (l *Listener) Close() {
	l.udp.Close()
}

// Handle is an internal goroutine that handles input.
func (l *Listener) Handle() {
	i := 0
	for {
		i++
		buf := make([]byte, 4096)
		log.Println("Reading")
		rlen, _, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
		}
		p, err := ParsePacket(buf[0:rlen])
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("%#v\n", string(buf[0:rlen]))
		log.Printf("%d %#v\n", i, p)
	}
}

// Listen to a specific address
func Listen(port int) (*Listener, error) {

	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("127.0.0.1"),
	}
	log.Println("Port", port)
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}
	c := Listener{
		udp: conn,
	}
	go c.Handle()
	return &c, nil
}
