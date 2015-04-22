package quic

import "encoding/binary"

// Frame Types
const (
	// Regular Frame Types

	PaddingFrame         = 0x0
	ResetStreamFrame     = 0x1
	ConnectionCloseFrame = 0x2
	GoAwayFrame          = 0x3
	WindowUpdateFrame    = 0x4
	BlockedFrame         = 0x5
	StopWaitingFrame     = 0x6
	PingFrame            = 0x7

	// Special Frame Types

	StreamFrame                 = 0x80
	AckFrameMask                = 0xC0
	AckFrame                    = 0x40
	CongestionFeedbackFrameMask = 0xE0
	CongestionFeedbackFrame     = 0x20
)

// Frame is an interface for the varying frames
type Frame interface {
}

// FrameStream represents a StreamFrame
type FrameStream struct {
	StreamID, Offset, DataLen uint64
	Fin                       bool
	Data                      string
}

// Constants for FrameStream
const (
	StreamIDMask = 0x03
	OffsetMask   = 0x1C
	DataLenMask  = 0x20
	FinMask      = 0x40
)

// FrameAck represents a AckFrame
type FrameAck struct {
	ReceivedEntropy                           byte
	LargestObserved, LargestObservedDeltaTime uint64
}

// Constants for FrameAck
const (
	SequenceNumberDeltaLenMask           = 0x03
	LargestObservedSequenceNumberLenMask = 0xC
)

// FrameStopWaiting represents a StopWaitingFrame
type FrameStopWaiting struct {
	SentEntropy       byte
	LeastUnackedDelta uint64
}

// FrameWindowUpdate represents a WindowUpdateFrame
type FrameWindowUpdate struct {
	StreamID, ByteOffset uint64
}

// FrameBlocked represents a BlockedFrame
type FrameBlocked struct {
	StreamID uint64
}

// ToBuf serializes a FrameBlocked into a byte array
func (f *FrameBlocked) ToBuf() ([]byte, error) {
	return []byte{CongestionFeedbackFrame}, nil
}

// FrameCongestionFeedback represents a CongestionFeedbackFrame
type FrameCongestionFeedback struct {
}

// ToBuf serializes a FrameCongestionFeedback into a byte array
func (f *FrameCongestionFeedback) ToBuf() ([]byte, error) {
	return []byte{CongestionFeedbackFrame}, nil
}

// FrameGoAway represents a GoAwayFrame
type FrameGoAway struct {
	ErrorCode, LastGoodStreamID uint64
	Reason                      string
}

// ToBuf serializes a FrameGoAway into a byte array
func (f *FrameGoAway) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+4+2+len(f.Reason))
	buf[0] = GoAwayFrame
	binary.PutUvarint(buf[1:5], f.ErrorCode)
	binary.PutUvarint(buf[5:9], f.LastGoodStreamID)
	binary.PutUvarint(buf[8:11], uint64(len(f.Reason)))
	copy(buf[11:], f.Reason)
	return buf, nil
}
