package bytes

import (
	obytes "bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeIntToBytes(t *testing.T) {
	var in int64 = 3<<56 + 2<<24 + 8<<16 + 5
	out := []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00, 0x05}
	if x := EncodeIntToBytes(in); !obytes.Equal(x, out) {
		t.Errorf("Encoding int to bytes failed with %s", hex.EncodeToString(x))
	}
}

func TestGetIntByte(t *testing.T) {
	var in int64 = 1<<9 + 1
	var out0 byte = 0x01
	var out1 byte = 0x02
	if a := getIntByte(in, 0); a != out0 {
		t.Errorf("Getting first byte failed with %x", a)
	}
	if b := getIntByte(in, 1); b != out1 {
		t.Errorf("Getting second byte failed with %x", b)
	}
}
