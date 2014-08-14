package state

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/word"
	"testing"
)

// newState returns a new state instance with constant value for testing purposes.
// Value is 0x2b73151628aed2a6abf7158809cf4f3c
func newState() *State {
	return &State{High: 0x2b73151628aed2a6, Low: 0xabf7158809cf4f3c}
}

func TestStateString(t *testing.T) {
	s := &State{High: 0x0003151628aed2a6, Low: 0x0007158809cf4f3c} // should be 0 padded
	out := "0003151628aed2a60007158809cf4f3c"
	if x := s.String(); out != x {
		t.Errorf("State stringify failed with %s", x)
	}
}

func TestNewStateFromBytes(t *testing.T) {
	s := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	out := State{High: 0x3c4fcf098815f7ab, Low: 0xa6d2ae2816157e2b}
	if x := NewStateFromBytes(s); *x != out {
		t.Errorf("New state from bytes failed with %s", x)
	}
}

func TestNewStateFromWords(t *testing.T) {
	s := []word.Word{word.Word(0x16157e2b), word.Word(0xa6d2ae28), word.Word(0x8815f7ab), word.Word(0x3c4fcf09)}
	out := &State{High: 0x3c4fcf098815f7ab, Low: 0xa6d2ae2816157e2b}
	if x := NewStateFromWords(s); *x != *out {
		t.Errorf("New state from words failed with %s", x)
	}
}

func TestGetBytes(t *testing.T) {
	s := &State{High: 0x3c4fcf098815f7ab, Low: 0xa6d2ae2816157e2b}
	out := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	if x := s.GetBytes(); !bytes.Equal(x, out) {
		t.Errorf("Get bytes failed with %s", hex.EncodeToString(x))
	}
}

func TestStateSub(t *testing.T) {
	s := &State{High: 0x0010203040506070, Low: 0x8090a0b0c0d0e0f0}
	out := State{High: 0x63cab7040953d051, Low: 0xcd60e0e7ba70e18c}
	if s.Sub(); *s != out {
		t.Errorf("State substitution failed with %v", s)
	}
}

func TestStateInvSub(t *testing.T) {
	s := newState()
	s.Sub() // already tested, just test if inverse
	if s.InvSub(); *s != *newState() {
		t.Errorf("State inverse substitution failed with %v", s)
	}
}

func TestStateShift(t *testing.T) {
	s := &State{High: 0xc81e07ab7e0e06dc, Low: 0x150d3590407bac36}
	out := State{High: 0x7e0dacab157b07dc, Low: 0x401e0690c80e3536}
	if s.Shift(); *s != out {
		t.Errorf("State shift failed with %v", s)
	}
}

func TestStateInvShift(t *testing.T) {
	s := newState()
	s.Shift() // already tested, just test if inverse
	if s.InvShift(); *s != *newState() {
		t.Errorf("State inverse shift failed with %v", s)
	}
}

func TestStateMix(t *testing.T) {
	s := &State{High: 0xe7d0caba51b770cd, Low: 0x04e160098ce05363}
	out := State{High: 0x1af9b91d293bbef7, Low: 0x92bcf5571564725f}
	if s.Mix(); *s != out {
		t.Errorf("Mix columns failed with %v", s)
	}
}

func TestStateInvMix(t *testing.T) {
	s := newState()
	s.Mix() // already tested, just test if inverse
	if s.InvMix(); *s != *newState() {
		t.Errorf("Mix inverse columns failed with %v", s)
	}
}

func TestStateXor(t *testing.T) {
	s := newState()
	xor := newState()
	out := State{High: 0, Low: 0}
	if s.Xor(*xor); *s != out {
		t.Errorf("State xor failed with %v", s)
	}
}

func testStateGetCol(t *testing.T, i int) {
	var high, low uint64
	var col uint32 = 0x12345678
	switch i {
	case 0, 1:
		low += uint64(col) << uint(i*32)
	case 2, 3:
		high += uint64(col) << uint((i-2)*32)
	}
	s := &State{High: high, Low: low}
	if out := s.GetCol(i); out != col {
		t.Errorf("Get column %d failed with %x", i, out)
	}
}

func testStateSetCol(t *testing.T, i int) {
	s := &State{High: 1<<64 - 1, Low: 1<<64 - 1}
	var col uint32 = 0x12345678
	s.SetCol(i, col)
	for j := 0; j < 4; j++ {
		out := s.GetCol(j) // assumes get column tested
		if j == i {
			if out != col {
				t.Errorf("Set column %d failed with %08x", j, out)
			}
		} else { // check that doesn't effect other columns
			if out != 1<<32-1 {
				t.Errorf("Set column %d failed because it also set column %d with %08x", i, j, out)
			}
		}
	}
}

func testStateGetRow(t *testing.T, i int) {
	var high, low uint64
	var row uint32 = 0x12345678
	low = 0x5600000078 << uint(i*8)
	high = 0x1200000034 << uint(i*8)
	s := &State{High: high, Low: low}
	if out := s.GetRow(i); out != row {
		t.Errorf("Get row %d failed with %x expected %x", i, out, row)
	}
}

func testStateSetRow(t *testing.T, i int) {
	s := &State{High: 1<<64 - 1, Low: 1<<64 - 1}
	var row uint32 = 0x12345678
	s.SetRow(i, row)
	for j := 0; j < 4; j++ {
		out := s.GetRow(j) // assumes get row tested
		if j == i {
			if out != row {
				t.Errorf("Set row %d failed with %08x", j, out)
			}
		} else { // check that doesn't effect other rows
			if out != 1<<32-1 {
				t.Errorf("Set row %d failed because it also set row %d with %08x", i, j, out)
			}
		}
	}
}

func TestStateGetSetCols(t *testing.T) {
	for i := 0; i < 4; i++ {
		testStateGetCol(t, i)
		testStateSetCol(t, i)
		testStateGetRow(t, i)
		testStateSetRow(t, i)
	}
}
