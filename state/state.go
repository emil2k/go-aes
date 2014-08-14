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
	High uint64 // most signficant 8 bytes of state, bytes 8-15
	Low  uint64 // least signficant 8 bytes of state, bytes 0-7
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
	return &State{High: high, Low: low}
}

// NewStateFromWords returns a new instance of state from passed word slice.
// Passed word slice must contain at least 4 bytes, only first 4 bytes used if more.
func NewStateFromWords(in []word.Word) *State {
	var low, high uint64
	low = uint64(in[0]) + uint64(in[1])<<32
	high = uint64(in[2]) + uint64(in[3])<<32
	return &State{High: high, Low: low}
}

// String provides a string representation of a State.
func (s State) String() string {
	return fmt.Sprintf("%016x%016x", s.High, s.Low)
}

// GetBytes returns a byte slice representing a byte slice.
// Bytes arranged in little endian order with the least signficant byte stored
// in the smallest index.
func (s *State) GetBytes() []byte {
	out := make([]byte, 16)
	tl, th := s.Low, s.High
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
	s.High = bytes.EachByte64(s.High, op)
	s.Low = bytes.EachByte64(s.Low, op)
}

// Sub substitutes all the bytes through the forward s-box.
func (s *State) Sub() {
	s.eachByte(rj.Sbox)
}

// InvSub substitutes all the bytes through the inverse s-box.
func (s *State) InvSub() {
	s.eachByte(rj.InvSbox)
}

// Shift rotates the bytes in the last 3 rows of the state.
// Row 0 is not shifted while, row 1, 2, and 3 are rotated 1, 2, 3 times respectively.
func (s *State) Shift() {
	for j := 1; j < 4; j++ {
		row := word.Word(s.GetRow(j))
		for i := 0; i < j; i++ {
			row.Rot()
		}
		s.SetRow(j, uint32(row))
	}
}

// InvShift rotates the bytes in the last 3 rows of the state, inverse of Shift.
func (s *State) InvShift() {
	for j := 1; j < 4; j++ {
		row := word.Word(s.GetRow(j))
		for i := 0; i < j; i++ {
			row.InvRot()
		}
		s.SetRow(j, uint32(row))
	}
}

// Mix mixes all the columns of the state.
func (s *State) Mix() {
	for i := 0; i < 4; i++ {
		s.MixCol(i)
	}
}

// InvMix mixes all the columns of the state.
func (s *State) InvMix() {
	for i := 0; i < 4; i++ {
		s.InvMixCol(i)
	}
}

var rjMul02, rjMul03, rjMul09, rjMul0e, rjMul0d, rjMul0b [256]byte // precomputed Rijndael multplication tables.

// init precomputes the rjMul02 and rjMul03 multiplication tables.
func init() {
	c := func(m byte, set *[256]byte) {
		for i := 0; i < 256; i++ {
			(*set)[i] = rj.Mul(m, byte(i))
		}
	}
	c(0x02, &rjMul02)
	c(0x03, &rjMul03)
	c(0x09, &rjMul09)
	c(0x0e, &rjMul0e)
	c(0x0d, &rjMul0d)
	c(0x0b, &rjMul0b)
}

// MixCol mixes the ith column in the state.
// Multiples the column modulo x^4+1 by the {03}x^3 + {01}x^2 + {01}x + {02}.
func (s *State) MixCol(i int) {
	c0, c1, c2, c3 := bytes.Split32(s.GetCol(i))
	var col uint32 = uint32(rj.Sum(rjMul02[c0], rjMul03[c1], c2, c3)) +
		uint32(rj.Sum(c0, rjMul02[c1], rjMul03[c2], c3))<<8 +
		uint32(rj.Sum(c0, c1, rjMul02[c2], rjMul03[c3]))<<16 +
		uint32(rj.Sum(rjMul03[c0], c1, c2, rjMul02[c3]))<<24
	s.SetCol(i, col)
}

// InvMixCol reverses the mixing of the ith column.
// Multiples the column modulo x^4+1 by the {0b}x^3 + {0d}x^2 + {09}x + {0e}.
func (s *State) InvMixCol(i int) {
	c0, c1, c2, c3 := bytes.Split32(s.GetCol(i))
	var col uint32 = uint32(rj.Sum(rjMul0e[c0], rjMul0b[c1], rjMul0d[c2], rjMul09[c3])) +
		uint32(rj.Sum(rjMul09[c0], rjMul0e[c1], rjMul0b[c2], rjMul0d[c3]))<<8 +
		uint32(rj.Sum(rjMul0d[c0], rjMul09[c1], rjMul0e[c2], rjMul0b[c3]))<<16 +
		uint32(rj.Sum(rjMul0b[c0], rjMul0d[c1], rjMul09[c2], rjMul0e[c3]))<<24
	s.SetCol(i, col)
}

// Xor xors input with the bytes in the state.
// relies on Word.Xor function
func (s *State) Xor(input State) {
	s.Low ^= input.Low
	s.High ^= input.High
}

// GetCol gets the ith column in the state.
func (s *State) GetCol(i int) uint32 {
	switch i {
	case 0:
		return uint32(s.Low)
	case 1:
		return uint32(s.Low >> 32)
	case 2:
		return uint32(s.High)
	case 3:
		return uint32(s.High >> 32)
	default:
		panic("column out of range")
	}
}

const (
	setColClear0 uint64 = 0xFFFFFFFF << (iota * 32)
	setColClear1
)

// SetCol sets the ith column in the state.
func (s *State) SetCol(i int, col uint32) {
	switch i {
	case 0:
		s.Low = s.Low&^setColClear0 + uint64(col)
	case 1:
		s.Low = s.Low&^setColClear1 + uint64(col)<<32
	case 2:
		s.High = s.High&^setColClear0 + uint64(col)
	case 3:
		s.High = s.High&^setColClear1 + uint64(col)<<32
	}
}

const (
	getByte0 uint64 = 0xFF << (iota * 8)
	getByte1
	getByte2
	getByte3
	getByte4
	getByte5
	getByte6
	getByte7
)

// GetRow gets the ith row in the state.
func (s *State) GetRow(i int) uint32 {
	switch i {
	case 0:
		return uint32(s.Low&getByte0 + (s.Low&getByte4)>>24 + (s.High&getByte0)<<16 + (s.High&(0xFF<<32))>>8)
	case 1:
		return uint32((s.Low&getByte1)>>8 + (s.Low&getByte5)>>32 + (s.High&getByte1)<<8 + (s.High&getByte5)>>16)
	case 2:
		return uint32((s.Low&getByte2)>>16 + (s.Low&getByte6)>>40 + s.High&getByte2 + (s.High&getByte6)>>24)
	case 3:
		return uint32((s.Low&getByte3)>>24 + (s.Low&getByte7)>>48 + (s.High&getByte3)>>8 + (s.High&getByte7)>>32)
	default:
		panic("row out of range")
	}
}

const (
	setRowClear0 uint64 = 0xFF000000FF << (iota * 8)
	setRowClear1
	setRowClear2
	setRowClear3
)

// SetRow sets the ith row in the state.
func (s *State) SetRow(i int, row uint32) {
	r0 := uint64(row) & getByte0
	r1 := uint64(row) & getByte1
	r2 := uint64(row) & getByte2
	r3 := uint64(row) & getByte3
	switch i {
	case 0:
		s.Low = s.Low&^setRowClear0 + r0 + r1<<24
		s.High = s.High&^setRowClear0 + r2>>16 + r3<<8
	case 1:
		s.Low = s.Low&^setRowClear1 + r0<<8 + r1<<32
		s.High = s.High&^setRowClear1 + r2>>8 + r3<<16
	case 2:
		s.Low = s.Low&^setRowClear2 + r0<<16 + r1<<40
		s.High = s.High&^setRowClear2 + r2 + r3<<24
	case 3:
		s.Low = s.Low&^setRowClear3 + r0<<24 + r1<<48
		s.High = s.High&^setRowClear3 + r2<<8 + r3<<32
	default:
		panic("row out of range")
	}
}
