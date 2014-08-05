package state

import (
	"fmt"

	rj "github.com/emil2k/go-aes/rijndael"
	"github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/word"
)

// State represents a temporary state of 16 bytes of the cipher.
// Organized in 4x4 byte matrix, input is stored in column major order.
type State struct {
	high uint64 // most signficant 8 bytes of state, bytes 8-15
	low  uint64 // least signficant 8 bytes of state, bytes 0-7
}

// NewStateFromBytes returns a new instance of state from passed byte slice.
// Passed byte slice must contain at least 16 bytes, only first 16 used if more.
func NewStateFromBytes(in []byte) *State {
	var low, high uint64
	for i := 0; i < 8; i++ {
		low += uint64(in[i]) << uint(i*8)
	}
	for j := 8; j < 16; j++ {
		high += uint64(in[j]) << uint((j-8)*8)
	}
	return &State{high: high, low: low}
}

// NewStateFromWords returns a new instance of state from passed word slice.
// Passed word slice must contain at least 4 bytes, only first 4 bytes used if more.
func NewStateFromWords(in []word.Word) *State {
	var low, high uint64
	low = uint64(in[0]) + uint64(in[1])<<32
	high = uint64(in[2]) + uint64(in[3])<<32
	return &State{high: high, low: low}
}

// String provides a string representation of a State
func (s *State) String() string {
	return fmt.Sprintf("%016x%016x", s.high, s.low)
}

// GetBytes returns a byte slice representing a byte slice.
// Bytes arranged in little endian order with the least signficant byte stored
// in the smallest index.
func (s *State) GetBytes() []byte {
	out := make([]byte, 16)
	tl, th := s.low, s.high
	for i := 0; i < 8; i++ {
		out[i] = byte(tl)
		tl >>= 8
	}
	for j := 8; j < 16; j++ {
		out[j] = byte(th)
		th >>= 8
	}
	return out
}

// eachByte performs the passed operation on each byte in the state.
func (s *State) eachByte(op func(in byte) byte) {
	s.high = bytes.EachByte64(s.high, op)
	s.low = bytes.EachByte64(s.low, op)
}

// Sub substitutes all the bytes through the forward s-box.
func (s *State) Sub() {
	s.eachByte(rj.Sbox)
}

// InvSub substitutes all the bytes through the inverse s-box
func (s *State) InvSub() {
	s.eachByte(rj.InvSbox)
}

// Shift rotates the bytes in the last 3 rows of the state
// row 0 is not shifted while, row 1, 2, and 3 are rotated 1, 2, 3 times respectively
func (s *State) Shift() {
	// TODO optimize to remove loops
	for j := 1; j < 4; j++ {
		row := word.Word(s.GetRow(j))
		for i := 0; i < j; i++ {
			row.Rot()
		}
		s.SetRow(j, uint32(row))
	}
}

// InvShift rotates the bytes in the last 3 rows of the state, inverse of Shift
func (s *State) InvShift() {
	// TODO optimize to remove loops
	for j := 1; j < 4; j++ {
		row := word.Word(s.GetRow(j))
		for i := 0; i < j; i++ {
			row.InvRot()
		}
		s.SetRow(j, uint32(row))
	}
}

// Mix mixes all the columns of the state
func (s *State) Mix() {
	for i := 0; i < 4; i++ {
		s.MixCol(i)
	}
}

// InvMix mixes all the columns of the state
func (s *State) InvMix() {
	for i := 0; i < 4; i++ {
		s.InvMixCol(i)
	}
}

// MixCol mixes the ith column in the state
// multiples the column modulo x^4+1 by the {03}x^3 + {01}x^2 + {01}x + {02}
func (s *State) MixCol(i int) {
	c0, c1, c2, c3 := bytes.Split32(s.GetCol(i))
	var col uint32 = uint32(rj.Sum(rj.Mul(0x02, c0), rj.Mul(0x03, c1), c2, c3)) +
		uint32(rj.Sum(c0, rj.Mul(0x02, c1), rj.Mul(0x03, c2), c3))<<8 +
		uint32(rj.Sum(c0, c1, rj.Mul(0x02, c2), rj.Mul(0x03, c3)))<<16 +
		uint32(rj.Sum(rj.Mul(0x03, c0), c1, c2, rj.Mul(0x02, c3)))<<24
	s.SetCol(i, col)
}

// InvMixCol reverses the mixing of the ith column
// multiples the column modulo x^4+1 by the {0b}x^3 + {0d}x^2 + {09}x + {0e}
func (s *State) InvMixCol(i int) {
	c0, c1, c2, c3 := bytes.Split32(s.GetCol(i))
	var col uint32 = uint32(rj.Sum(rj.Mul(0x0e, c0), rj.Mul(0x0b, c1), rj.Mul(0x0d, c2), rj.Mul(0x09, c3))) +
		uint32(rj.Sum(rj.Mul(0x09, c0), rj.Mul(0x0e, c1), rj.Mul(0x0b, c2), rj.Mul(0x0d, c3)))<<8 +
		uint32(rj.Sum(rj.Mul(0x0d, c0), rj.Mul(0x09, c1), rj.Mul(0x0e, c2), rj.Mul(0x0b, c3)))<<16 +
		uint32(rj.Sum(rj.Mul(0x0b, c0), rj.Mul(0x0d, c1), rj.Mul(0x09, c2), rj.Mul(0x0e, c3)))<<24
	s.SetCol(i, col)
}

// Xor xors input with the bytes in the state
// relies on Word.Xor function
func (s *State) Xor(input State) {
	s.low ^= input.low
	s.high ^= input.high
}

// GetCol gets the ith column in the state.
func (s *State) GetCol(i int) uint32 {
	switch i {
	case 0:
		return uint32(s.low)
	case 1:
		return uint32(s.low >> 32)
	case 2:
		return uint32(s.high)
	case 3:
		return uint32(s.high >> 32)
	default:
		panic("column out of range")
	}
}

// SetCol sets the ith column in the state.
func (s *State) SetCol(i int, col uint32) {
	var clear uint64 = 0xFFFFFFFF
	switch i {
	case 0:
		s.low = s.low&^clear + uint64(col)
	case 1:
		s.low = s.low&^(clear<<32) + uint64(col)<<32
	case 2:
		s.high = s.high&^clear + uint64(col)
	case 3:
		s.high = s.high&^(clear<<32) + uint64(col)<<32
	}
}

// GetRow gets the ith row in the state.
// TODO rewrite this function
func (s *State) GetRow(i int) uint32 {
	switch i {
	case 0:
		return uint32(s.low&0xFF + (s.low&(0xFF<<32))>>24 + (s.high&(0xFF))<<16 + (s.high&(0xFF<<32))>>8)
	case 1:
		return uint32((s.low&(0xFF<<8))>>8 + (s.low&(0xFF<<40))>>32 + (s.high&(0xFF<<8))<<8 + (s.high&(0xFF<<40))>>16)
	case 2:
		return uint32((s.low&(0xFF<<16))>>16 + (s.low&(0xFF<<48))>>40 + s.high&(0xFF<<16) + (s.high&(0xFF<<48))>>24)
	case 3:
		return uint32((s.low&(0xFF<<24))>>24 + (s.low&(0xFF<<56))>>48 + (s.high&(0xFF<<24))>>8 + (s.high&(0xFF<<56))>>32)
	default:
		panic("row out of range")
	}
}

// SetRow sets the ith row in the state.
func (s *State) SetRow(i int, row uint32) {
	var clear uint64 = 0xFF000000FF
	r0, r1, r2, r3 := bytes.Split32(row)
	s.low &^= clear << uint(i*8)
	s.high &^= clear << uint(i*8)
	s.low += uint64(r0) << uint(i*8)
	s.low += uint64(r1) << uint(i*8+32)
	s.high += uint64(r2) << uint(i*8)
	s.high += uint64(r3) << uint(i*8+32)
}
