package rijndael

import "testing"

func TestAddSub(t *testing.T) {
	a := byte(0x31)
	b := byte(0x11)
	if c := Add(a, b); c != 0x20 {
		t.Errorf("Rijndael field addition failed with %v", c)
	}
	if c := Sub(a, b); c != 0x20 {
		t.Errorf("Rijndael field subtraction failed with %v", c)
	}
}

func TestSum(t *testing.T) {
	a := byte(0x31)
	b := byte(0x11)
	c := byte(0x01)
	if sum := Sum(a, b, c); sum != 0x21 {
		t.Errorf("Rijndael field sum failed with %v", sum)
	}
}

func TestMul(t *testing.T) {
	a := byte(0x53)
	b := byte(0xca)
	if c := Mul(a, b); c != 0x01 {
		t.Errorf("Rijndael field multiplication failed with %v", c)
	}
}
