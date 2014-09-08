package word

import (
	"fmt"
	"github.com/emil2k/go-aes/util/bytes"
	rj "github.com/emil2k/go-math/rijndael"
)

// Word represents 4 bytes of data.
type Word uint32

// String provides a string representation of a Word
func (w Word) String() string {
	return fmt.Sprintf("%08x", uint32(w))
}

// Rot rotates a Word's bytes down by 1 spot.
// Moves the least significant byte to most signficant position, shifting all other bytes down.
func (w *Word) Rot() {
	*w = (0xFF&(*w))<<24 + (0xFFFFFF00&(*w))>>8
}

// InvRot rotates a Word's bytes up by 1 spot, inverse of Rot.
// Moves the most signficant byte to least signficant position, shifting all other bytes up.
func (w *Word) InvRot() {
	*w = (0x00FFFFFF&(*w))<<8 + (0xFF000000&(*w))>>24
}

// Sub substitutes a Word's bytes through a Rijndael forward s-box
func (w *Word) Sub() {
	*w = Word(bytes.EachByte32(uint32(*w), rj.Sbox))
}

// InvSub substitutes a Word's bytes through a Rijndael inverse s-box
func (w *Word) InvSub() {
	*w = Word(bytes.EachByte32(uint32(*w), rj.InvSbox))
}

// Xor xors the input word with the word.
func (w *Word) Xor(input Word) {
	(*w) ^= input
}
