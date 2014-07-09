package rijndael

import "testing"

func TestAddSub(t *testing.T) {
	a := rjnum(0x31)
	b := rjnum(0x11)
	if c := Add(a, b); c != 0x20 {
		t.Errorf("Rijndael field addition failed with %x", c)
	}
	if c := Sub(a, b); c != 0x20 {
		t.Errorf("Rijndael field subtraction failed with %x", c)
	}
}

func TestMul(t *testing.T) {
	a := rjnum(0x53)
	b := rjnum(0xca)
	if c := Mul(a, b); c != 0x01 {
		t.Errorf("Rijndael field multiplication failed with %v", c)
	}
}
