package quic

import (
	"encoding/binary"
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
		log.Println(string(buf[0:rlen]))
		log.Printf("%d %#v\n", i, p)
	}
}

// Public Flags
const (
	// QuicVersion - LSB 0x1 has value 1 iff the packet contains a Quic Version.  This bit must be set by a client in all packets until confirmation from a server arrives agreeing to the proposed version is received by the client.  A server indicates agreement on a version by sending packets without setting this bit.
	QuicVersion = 0x1
	// PublicReset - Bit at location, 0x2, is set to indicate that the packet is a Public Reset packet.
	PublicReset = 0x2
	// DataPacket is the bitmask for a data packet. If version and public reset aren't set.
	DataPacket = 0x3

	// ConnIDBitMask - Pair of bits, included in 0xC, together indicate the size of the connection ID that is present in the packet, but should be set to set to 0xC in all packets until agreeably negotiated to a different value, for a given direction (e.g., client may request fewer bytes of the connection id be presented).  Within this 2 bit mask:
	ConnIDBitMask = 0xC
	ConnID8Bytes  = 0xC
	ConnID4Bytes  = 0x8
	ConnID1Byte   = 0x4
	ConnIDOmmited = 0x0

	// SequenceNumberBitMask - Pair of bits included in 0x30 indicate the number of low-order-bytes of the packet sequence number that are present in each packet.  Within this 2 bit mask:
	SequenceNumberBitMask = 0x30
	SequenceNumber6Bytes  = 0x30
	SequenceNumber4Bytes  = 0x20
	SequenceNumber2Bytes  = 0x10
	SequenceNumber1Byte   = 0x00
)

// Private Flags
const (
	// FlagEntropy - for data packets, signifies that this packet contains the 1 bit of entropy, for fec packets, contains the xor of the entropy of protected packets.
	FlagEntropy = 0x01
	// FlagFECGroup - indicates whether the fec byte is present.
	FlagFECGroup = 0x02
	// FlagFEC - signifies that this packet represents an FEC packet.
	FlagFEC = 0x04
)

// Packet represents a packet
type Packet struct {
	PublicFlags                         byte
	ConnID, QuicVersion, SequenceNumber uint64
	PrivateFlags                        byte
	FECGroupNumber                      uint64
	Type                                byte
}

// ParsePacket parses a byte array and returns the corresponding packet
func ParsePacket(buf []byte) (*Packet, error) {
	p := Packet{}
	i := 0
	p.PublicFlags = buf[i]
	i++

	// Connection ID
	connIDLen := 0
	switch p.PublicFlags & ConnIDBitMask {
	case ConnID8Bytes:
		connIDLen = 8
	case ConnID4Bytes:
		connIDLen = 4
	case ConnID1Byte:
		connIDLen = 1
	}
	n := 0
	p.ConnID, n = binary.Uvarint(buf[i : i+connIDLen])
	if n <= 0 {
		log.Println("n", n)
	}
	i += connIDLen

	// Quic Version
	if p.PublicFlags&QuicVersion == QuicVersion {
		p.QuicVersion, n = binary.Uvarint(buf[i : i+4])
		if n <= 0 {
			log.Println("n", n)
		}
		i += 4
	}

	p.Type = p.PublicFlags & DataPacket

	// Sequence Number
	sequenceNumberLen := 1
	switch p.PublicFlags & ConnIDBitMask {
	case SequenceNumber6Bytes:
		sequenceNumberLen = 6
	case SequenceNumber4Bytes:
		sequenceNumberLen = 4
	case SequenceNumber2Bytes:
		sequenceNumberLen = 2
	}
	p.SequenceNumber, n = binary.Uvarint(buf[i : i+sequenceNumberLen])
	if n <= 0 {
		log.Println("n", n)
	}
	i += sequenceNumberLen

	p.PrivateFlags = buf[i]
	i++
	if p.PrivateFlags&FlagFECGroup == FlagFECGroup {
		offset := uint64(buf[i])
		p.FECGroupNumber = p.SequenceNumber - offset
		i++
	}
	log.Println("Remainder", string(buf[i:]))

	return &p, nil
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
