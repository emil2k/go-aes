package word

import "bytes"
import "testing"

func TestWordRot(t *testing.T) {
	w := Word([]byte{0x90, 0x01, 0x02, 0x03})
	w.Rot(1)
	if !bytes.Equal(w, []byte{0x01, 0x02, 0x03, 0x90}) {
		t.Errorf("Rotation failed with %v", w)
	}
	w.Rot(3)
	if !bytes.Equal(w, []byte{0x90, 0x01, 0x02, 0x03}) {
		t.Errorf("Rotation failed with %v", w)
	}
}

func TestWordInvRot(t *testing.T) {
	w := Word([]byte{0x90, 0x01, 0x02, 0x03})
	w.InvRot(1)
	if !bytes.Equal(w, []byte{0x03, 0x90, 0x01, 0x02}) {
		t.Errorf("Inverse rotation failed with %v", w)
	}
	w.InvRot(3)
	if !bytes.Equal(w, []byte{0x90, 0x01, 0x02, 0x03}) {
		t.Errorf("Inverse rotation failed with %v", w)
	}
}

func TestWordSub(t *testing.T) {
	w := Word([]byte{0xC3, 0x89, 0xAF, 0xF8})
	w.Sub()
	if !bytes.Equal(w, []byte{0x2E, 0xA7, 0x79, 0x41}) {
		t.Errorf("Substitution failed with %v", w)
	}
}

func TestWordInvSub(t *testing.T) {
	w := Word([]byte{0x2E, 0xA7, 0x79, 0x41})
	w.InvSub()
	if !bytes.Equal(w, []byte{0xC3, 0x89, 0xAF, 0xF8}) {
		t.Errorf("Substitution failed with %v", w)
	}
}

func TestWordXor(t *testing.T) {
	w := Word([]byte{0x2E, 0xA7, 0x79, 0x41})
	xor := Word([]byte{0x2E, 0xA7, 0x79})
	w.Xor(xor)
	if !bytes.Equal(w, []byte{0x00, 0x00, 0x00, 0x41}) {
		t.Errorf("Xor failed with %v", w)
	}
}
