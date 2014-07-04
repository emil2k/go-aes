package key

import "fmt"

// Word holds 4 bytes
type Word []byte

// String provides a string representation of a Word
func (w Word) String() string {
	return fmt.Sprintf("Word : %x", []byte(w))
}

// Rot rotates a Word's bytes down
func (w Word) Rot() {
	t := make([]byte, len(w))
	copy(t, w)
	for i, v := range t {
		w[(i+len(w)-1)%len(w)] = v
	}
}

// InvRot rotates a Word's bytes up, inverse of Rot
func (w Word) InvRot() {
	t := make([]byte, len(w))
	copy(t, w)
	for i, v := range t {
		w[(i+1)%len(w)] = v
	}
}

// TODO substitute, xor and any inverses
