package cipher

import (
	"bytes"
	"testing"

	"github.com/emil2k/go-aes/key"
	"github.com/emil2k/go-aes/state"
)

func TestCipherString(t *testing.T) {
	c := Cipher{state: state.NewStateFromBytes([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})}
	out := "ffeeddccbbaa99887766554433221100"
	if x := c.String(); x != out {
		t.Errorf("Cipher stringify failed with %s", x)
	}
}

func TestNewCipher(t *testing.T) {
	if c := NewCipher(CK128); c.nk != 4 || c.nr != 10 {
		t.Errorf("New 128 bit cipher failed")
	}
	if c := NewCipher(CK192); c.nk != 6 || c.nr != 12 {
		t.Errorf("New 128 bit cipher failed")
	}
	if c := NewCipher(CK256); c.nk != 8 || c.nr != 14 {
		t.Errorf("New 128 bit cipher failed")
	}
}

func TestNewCipherPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != "invalid cipher key size selected" {
			t.Errorf("Invalid cipher key size panic failed.")
		}
	}()
	_ = NewCipher(CipherKeySize(734))
}

func TestAddRoundKey(t *testing.T) {
	c := NewCipher(CK128)
	ck := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f} // cipher key
	in := *state.NewStateFromBytes([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	c.initCipher(in, ck, false)
	out := []byte{0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0}
	if c.AddRoundKey(); !bytes.Equal(c.state.GetBytes(), out) {
		t.Errorf("Add round key failed with %v", c.state)
	}
}

func TestGetRoundKey(t *testing.T) {
	ck := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f} // cipher key
	r1 := []byte{0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe} // round 1 key
	c := Cipher{key: key.NewKey(4, ck)}
	if out0 := c.GetRoundKey(0); !bytes.Equal(out0.GetBytes(), ck) {
		t.Errorf("Get round key for round 0 failed with %v", out0)
	}
	if out1 := c.GetRoundKey(1); !bytes.Equal(out1.GetBytes(), r1) {
		t.Errorf("Get round key for round 1 failed with %v", out1)
	}
}

func TestEncrypt(t *testing.T) {
	c := NewCipher(CK128)
	ck := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f} // cipher key
	in := *state.NewStateFromBytes([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	out := *state.NewStateFromBytes([]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a})
	if x := c.Encrypt(in, ck); x != out {
		t.Errorf("Encrypt failed with %s", x)
	}
}

func TestDecrypt(t *testing.T) {
	c := NewCipher(CK128)
	ck := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f} // cipher key
	ct := *state.NewStateFromBytes([]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a})
	out := *state.NewStateFromBytes([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	if x := c.Decrypt(ct, ck); x != out {
		t.Errorf("Decrypt failed with %s", x)
	}
}
