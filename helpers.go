package quic

import (
	"encoding/binary"
	"log"
	"math"
)

// FloatToUFloat16 converts a float64 into a 16 bit unsigned float with 11 explicit bits of mantissa and 5 bits of explicit exponent byte array.
func FloatToUFloat16(a float64) []byte {
	bits := math.Float64bits(a)
	buf := make([]byte, 8)
	binary.PutUvarint(buf, bits)
	log.Println(buf)
	return buf
}
