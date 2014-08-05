package bytes

import (
	"testing"
)

func TestEachByte64(t *testing.T) {
	var in, out uint64 = 0, 0x0101010101010101
	op := func(in byte) byte {
		return 0x01
	}
	if x := EachByte64(in, op); x != out {
		t.Errorf("Operation on each byte failed with %x", x)
	}
}

func TestEachByte32(t *testing.T) {
	var in, out uint32 = 0, 0x01010101
	op := func(in byte) byte {
		return 0x01
	}
	if x := EachByte32(in, op); x != out {
		t.Errorf("Operation on each byte failed with %x", x)
	}
}
