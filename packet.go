package quic

import (
	"encoding/binary"
	"log"
)

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
	Frames                              []Frame
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
	if p.PrivateFlags&FlagFECGroup > 0 {
		offset := uint64(buf[i])
		p.FECGroupNumber = p.SequenceNumber - offset
		i++
	}
	// DataPacket
	if p.Type == 0x0 {
		log.Println("DATA PACKET")
	} else if p.PrivateFlags&FlagFEC > 0 {
		log.Println("TODO: FEC PACKETS")
		return &p, nil
	} else {
		//log.Println("unknown packet type", p.Type)
	}
	// Frames
	for i < len(buf) {
		typeField := buf[i]
		i++
		if typeField&StreamFrame > 0 {
			log.Println("StreamFrame")
			frame := FrameStream{}

			// Stream ID
			streamIDLen := int(typeField&StreamIDMask) + 1
			frame.StreamID, n = binary.Uvarint(buf[i : i+streamIDLen])
			i += streamIDLen
			if n <= 0 {
				log.Println("n", n)
			}

			// Offset
			offsetLen := int(typeField & OffsetMask >> 2)
			if offsetLen > 0 {
				offsetLen++
				frame.Offset, n = binary.Uvarint(buf[i : i+offsetLen])
				i += offsetLen
				if n <= 0 {
					log.Println("n", n)
				}
			}

			// DataLen
			dataLenPresent := typeField&DataLenMask > 0
			if dataLenPresent {
				frame.DataLen, n = binary.Uvarint(buf[i : i+2])
				i += 2
			}

			// Fin
			frame.Fin = typeField&FinMask > 0

			if dataLenPresent {
				frame.Data = string(buf[i : i+int(frame.DataLen)])
				i += int(frame.DataLen)
			} else if !frame.Fin {
				frame.Data = string(buf[i:])
				i += len(buf[i:])
			}
			p.Frames = append(p.Frames, frame)
			continue
		} else if typeField&AckFrameMask == AckFrame {
			log.Println("AckFrame")
			frame := FrameAck{}

			p.Frames = append(p.Frames, frame)
		} else if typeField&CongestionFeedbackFrameMask == CongestionFeedbackFrame {
			/*log.Println("CongestionFeedbackFrame")
			frame := FrameCongestionFeedback{}
			// Not currently used according to docs but sent anyways. :|
			p.Frames = append(p.Frames, frame)*/
			continue
		} else {
			switch typeField {
			case PaddingFrame:
				log.Println("PaddingFrame")
				p.Frames = append(p.Frames, &FramePadding{})
				// reset of packet is padding, nothing needs to happen
				break
			case ResetStreamFrame:
				log.Println("ResetStreamFrame")
				frame := FrameResetStream{}
				frame.StreamID, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				frame.ErrorCode, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				p.Frames = append(p.Frames, frame)
				continue
			case ConnectionCloseFrame:
				log.Println("ConnectionCloseFrame")
				frame := FrameConnectionClose{}
				frame.ErrorCode, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				length, n2 := binary.Uvarint(buf[i : i+2])
				i += 2
				if n2 <= 0 {
					log.Println("n", n)
				}
				frame.Reason = string(buf[i : i+int(length)])
				i += int(length)
				p.Frames = append(p.Frames, frame)
				continue
			case GoAwayFrame:
				log.Println("GoAwayFrame")
				frame := FrameGoAway{}
				frame.ErrorCode, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				frame.LastGoodStreamID, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				length, n2 := binary.Uvarint(buf[i : i+2])
				i += 2
				if n2 <= 0 {
					log.Println("n", n)
				}
				frame.Reason = string(buf[i : i+int(length)])
				i += int(length)
				p.Frames = append(p.Frames, frame)
				continue
			case WindowUpdateFrame:
				log.Println("WindowUpdateFrame")
				frame := FrameWindowUpdate{}
				frame.StreamID, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				frame.ByteOffset, n = binary.Uvarint(buf[i : i+8])
				i += 8
				if n <= 0 {
					log.Println("n", n)
				}
				p.Frames = append(p.Frames, frame)
				continue
			case BlockedFrame:
				log.Println("BlockedFrame")
				frame := FrameBlocked{}
				frame.StreamID, n = binary.Uvarint(buf[i : i+4])
				i += 4
				if n <= 0 {
					log.Println("n", n)
				}
				p.Frames = append(p.Frames, frame)
				continue
			case StopWaitingFrame:
				log.Println("StopWaitingFrame")
				frame := FrameStopWaiting{}
				frame.SentEntropy = buf[i]
				i++
				frame.LeastUnackedDelta, n = binary.Uvarint(buf[i : i+sequenceNumberLen])
				i += sequenceNumberLen
				if n <= 0 {
					log.Println("n", n)
				}
				p.Frames = append(p.Frames, frame)
				continue
			case PingFrame:
				log.Println("PingFrame")
				p.Frames = append(p.Frames, &FramePing{})
				continue
			default:
				log.Println("UnknownFrame", typeField)
			}
		}
		log.Println("UNHANDLED FRAME BREAKING!", typeField)
		break
	}
	//log.Println("Remainder", string(buf[i:]))

	return &p, nil
}
