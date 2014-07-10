package state

import (
	"fmt"

	rj "github.com/emil2k/aes/rijndael"
	"github.com/emil2k/aes/word"
)

// State represents a temporary state of 16 bytes of the cipher
// organized in 4x4 byte matrix, input sequentially fills columns from top to bottom
type State []byte

// String provides a string representation of a State
func (s *State) String() string {
	var out string
	for j := 0; j < 4; j++ {
		out += fmt.Sprintf("%v ", word.Word(s.GetRow(j)))
	}
	return out
}

// Sub substitutes all the bytes through the forward s-box
func (s *State) Sub() {
	word.Word(*s).Sub()
}

// InvSub substitutes all the bytes through the inverse s-box
func (s *State) InvSub() {
	word.Word(*s).InvSub()
}

// Shift rotates the bytes in the last 3 rows of the state
// row 0 is not shifted while, row 1, 2, and 3 are rotated 1, 2, 3 times respectively
func (s *State) Shift() {
	for j := 1; j < 4; j++ {
		row := s.GetRow(j)
		word.Word(row).Rot(j)
		s.SetRow(j, &row)
	}
}

// InvShift rotates the bytes in the last 3 rows of the state, inverse of Shift
func (s *State) InvShift() {
	for j := 1; j < 4; j++ {
		row := s.GetRow(j)
		word.Word(row).InvRot(j)
		s.SetRow(j, &row)
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
	t := make([]byte, 4)
	col := s.GetCol(i)
	t[0] = rj.Sum(rj.Mul(0x02, col[0]), rj.Mul(0x03, col[1]), col[2], col[3])
	t[1] = rj.Sum(col[0], rj.Mul(0x02, col[1]), rj.Mul(0x03, col[2]), col[3])
	t[2] = rj.Sum(col[0], col[1], rj.Mul(0x02, col[2]), rj.Mul(0x03, col[3]))
	t[3] = rj.Sum(rj.Mul(0x03, col[0]), col[1], col[2], rj.Mul(0x02, col[3]))
	s.SetCol(i, &t)
}

// InvMixCol reverses the mixing of the ith column
// multiples the column modulo x^4+1 by the {0b}x^3 + {0d}x^2 + {09}x + {0e}
func (s *State) InvMixCol(i int) {
	t := make([]byte, 4)
	col := s.GetCol(i)
	t[0] = rj.Sum(rj.Mul(0x0e, col[0]), rj.Mul(0x0b, col[1]), rj.Mul(0x0d, col[2]), rj.Mul(0x09, col[3]))
	t[1] = rj.Sum(rj.Mul(0x09, col[0]), rj.Mul(0x0e, col[1]), rj.Mul(0x0b, col[2]), rj.Mul(0x0d, col[3]))
	t[2] = rj.Sum(rj.Mul(0x0d, col[0]), rj.Mul(0x09, col[1]), rj.Mul(0x0e, col[2]), rj.Mul(0x0b, col[3]))
	t[3] = rj.Sum(rj.Mul(0x0b, col[0]), rj.Mul(0x0d, col[1]), rj.Mul(0x09, col[2]), rj.Mul(0x0e, col[3]))
	s.SetCol(i, &t)
}

// GetCol gets the ith column in the state
func (s *State) GetCol(i int) []byte {
	col := make([]byte, 4)
	copy(col, (*s)[i*4:i*4+4])
	return col
}

// SetCol sets the ith column in the state
func (s *State) SetCol(i int, col *[]byte) {
	copy((*s)[i*4:i*4+4], *col)
}

// GetRow gets the ith row in the state
func (s *State) GetRow(i int) []byte {
	row := make([]byte, 4)
	for j := 0; j < 4; j++ {
		row[j] = (*s)[j*4+i]
	}
	return row
}

// SetRow sets the ith row in the state
func (s *State) SetRow(i int, row *[]byte) {
	for j := 0; j < 4; j++ {
		(*s)[j*4+i] = (*row)[j]
	}
}
