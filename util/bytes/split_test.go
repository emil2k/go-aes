package bytes

import (
	"testing"
)

func TestSplit32(t *testing.T) {
	b0, b1, b2, b3 := Split32(0x03020100)
	if b0 != 0x00 ||
		b1 != 0x01 ||
		b2 != 0x02 ||
		b3 != 0x03 {
		t.Error("Spliting 32 bit failed : ", b0, b1, b2, b3)
	}
}

func TestJoin32(t *testing.T) {
	var in uint32 = 0x03020100
	b0, b1, b2, b3 := Split32(in) // assumes split tested
	b := []byte{b0, b1, b2, b3}
	if out := Join32(b); out != in {
		t.Errorf("Join 32 bit failed with %08x", out)
	}
	if b[0] != b0 {
		t.Errorf("First element wrong")
	}
}
