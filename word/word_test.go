package word

import "testing"

// newWord generates a new word for testing purposes.
// Value is constant at 0x6CA2C19D.
func newWord() *Word {
	w := Word(0x6CA2C19D)
	return &w
}

func TestWordString(t *testing.T) {
	w := Word(0x00A2C19D) // test 0 padding
	out := "00a2c19d"
	if x := w.String(); x != out {
		t.Errorf("Word stringify failed with %s", x)
	}
}

func TestWordRot(t *testing.T) {
	w := newWord()
	w.Rot()
	if *w != Word(0x9D6CA2C1) {
		t.Errorf("Rotation failed with %v", w)
	}
}

func TestWordInvRot(t *testing.T) {
	w := newWord()
	w.InvRot()
	if *w != Word(0xA2C19D6C) {
		t.Errorf("Inverse rotation failed with %v", w)
	}
}

func TestWordSub(t *testing.T) {
	w := newWord()
	w.Sub()
	if *w != 0x503A785E {
		t.Errorf("Substitution failed with %v", w)
	}
}

func TestWordInvSub(t *testing.T) {
	w := newWord()
	w.Sub() // this should have already been tested separately
	w.InvSub()
	if *w != *newWord() {
		t.Errorf("Substitution failed with %v", w)
	}
}

func TestWordXor(t *testing.T) {
	w := newWord()
	w.Xor(*newWord())
	if *w != 0x00000000 {
		t.Errorf("Xor failed with %v", w)
	}
}
