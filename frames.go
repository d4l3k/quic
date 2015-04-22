package quic

import (
	"encoding/binary"
	"errors"
)

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
	ToBuf() ([]byte, error)
}

// FrameStream represents a StreamFrame
type FrameStream struct {
	StreamID, Offset, DataLen uint64
	Fin                       bool
	Data                      string
}

// ToBuf serializes a frame into a byte array
// TODO: Implement variable length StreamID and optional data length
func (f FrameStream) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+8+2+len(f.Data))
	buf[0] = StreamFrame | 0x3f
	if f.Fin {
		buf[0] = buf[0] | 0x40
	}
	binary.PutUvarint(buf[1:5], f.StreamID)
	binary.PutUvarint(buf[5:9], f.Offset)
	binary.PutUvarint(buf[9:11], uint64(len(f.Data)))
	copy(buf[11:], f.Data)
	return buf, nil
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

// ToBuf serializes a frame into a byte array
func (f FrameAck) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+1+6+2+1)
	buf[0] = AckFrame
	buf[1] = f.ReceivedEntropy
	binary.PutUvarint(buf[2:8], f.LargestObserved)
	binary.PutUvarint(buf[8:10], f.LargestObservedDeltaTime)
	// TODO rest of this shit.
	return buf, errors.New("frame FrameAck not fully implemented")
}

// Constants for FrameAck
const (
	SequenceNumberDeltaLenMask           = 0x03
	LargestObservedSequenceNumberLenMask = 0xC
)

// FrameResetStream represents a ResetStreamFrame
type FrameResetStream struct {
	StreamID, ErrorCode uint64
}

// ToBuf serializes a frame into a byte array
func (f FrameResetStream) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+4)
	buf[0] = ResetStreamFrame
	binary.PutUvarint(buf[1:5], f.StreamID)
	binary.PutUvarint(buf[5:9], f.ErrorCode)
	return buf, nil
}

// FrameStopWaiting represents a StopWaitingFrame
type FrameStopWaiting struct {
	SentEntropy       byte
	LeastUnackedDelta uint64
}

// ToBuf serializes a frame into a byte array
// TODO Variable length delta
func (f FrameStopWaiting) ToBuf() ([]byte, error) {
	buf := make([]byte, 2+6)
	buf[0] = StopWaitingFrame
	buf[1] = f.SentEntropy
	binary.PutUvarint(buf[2:8], f.LeastUnackedDelta)
	return buf, nil
}

// FrameWindowUpdate represents a WindowUpdateFrame
type FrameWindowUpdate struct {
	StreamID, ByteOffset uint64
}

// ToBuf serializes a frame into a byte array
func (f FrameWindowUpdate) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+8)
	buf[0] = WindowUpdateFrame
	binary.PutUvarint(buf[1:5], f.StreamID)
	binary.PutUvarint(buf[5:13], f.ByteOffset)
	return buf, nil
}

// FrameBlocked represents a BlockedFrame
type FrameBlocked struct {
	StreamID uint64
}

// ToBuf serializes a FrameBlocked into a byte array
func (f FrameBlocked) ToBuf() ([]byte, error) {
	buf := make([]byte, 5)
	buf[0] = BlockedFrame
	binary.PutUvarint(buf[1:5], f.StreamID)
	return buf, nil
}

// FrameCongestionFeedback represents a CongestionFeedbackFrame
type FrameCongestionFeedback struct {
}

// ToBuf serializes a FrameCongestionFeedback into a byte array
func (f FrameCongestionFeedback) ToBuf() ([]byte, error) {
	return []byte{CongestionFeedbackFrame}, nil
}

// FramePing represents a PingFrame
type FramePing struct {
}

// ToBuf serializes a FramePing into a byte array
func (f FramePing) ToBuf() ([]byte, error) {
	return []byte{PingFrame}, nil
}

// FramePadding represents a PaddingFrame
type FramePadding struct {
}

// ToBuf serializes a FramePadding into a byte array
func (f FramePadding) ToBuf() ([]byte, error) {
	return []byte{PaddingFrame}, nil
}

// FrameConnectionClose represents a ConnectionCloseFrame
type FrameConnectionClose struct {
	ErrorCode uint64
	Reason    string
}

// ToBuf serializes a FrameConnectionClose into a byte array
func (f FrameConnectionClose) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+2+len(f.Reason))
	buf[0] = ConnectionCloseFrame
	binary.PutUvarint(buf[1:5], f.ErrorCode)
	binary.PutUvarint(buf[5:7], uint64(len(f.Reason)))
	copy(buf[7:], f.Reason)
	return buf, nil
}

// FrameGoAway represents a GoAwayFrame
type FrameGoAway struct {
	ErrorCode, LastGoodStreamID uint64
	Reason                      string
}

// ToBuf serializes a FrameGoAway into a byte array
func (f FrameGoAway) ToBuf() ([]byte, error) {
	buf := make([]byte, 1+4+4+2+len(f.Reason))
	buf[0] = GoAwayFrame
	binary.PutUvarint(buf[1:5], f.ErrorCode)
	binary.PutUvarint(buf[5:9], f.LastGoodStreamID)
	binary.PutUvarint(buf[8:11], uint64(len(f.Reason)))
	copy(buf[11:], f.Reason)
	return buf, nil
}
