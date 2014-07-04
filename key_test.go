package key

import "bytes"
import "testing"

func TestWordRot(t *testing.T) {
	w := Word([]byte{0x90, 0x01, 0x02, 0x03})
	w.Rot()
	if !bytes.Equal(w, []byte{0x01, 0x02, 0x03, 0x90}) {
		t.Errorf("Rotation failed with %v", w)
	}
}

func TestWordInvRot(t *testing.T) {
	w := Word([]byte{0x90, 0x01, 0x02, 0x03})
	w.InvRot()
	if !bytes.Equal(w, []byte{0x03, 0x90, 0x01, 0x02}) {
		t.Errorf("Inverse rotation failed with %v", w)
	}
}
