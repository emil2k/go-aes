package bytes

import (
	"testing"
)

func TestBinaryString(t *testing.T) {
	b := uint64(0x8A8A8A8A8A8A8A8A)
	bs := "8a8a8a8a8a8a8a8a : 1000101010001010100010101000101010001010100010101000101010001010"
	if out := BinaryString(b); out != bs {
		t.Errorf("Binary string failed with %s", out)
	}
}
