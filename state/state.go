package state

import (
	"fmt"

	"github.com/emil2k/aes/word"
)

// State represents a temporary state of 16 bytes of the cipher
// organized in 4x4 byte matrix, input sequentially fills columns from top to bottom
type State []byte

// String provides a string representation of a State
func (s *State) String() string {
	var out string
	for j := 0; j < 4; j++ {
		out += fmt.Sprintf("%v \n", word.Word(s.GetRow(j)).String())
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
