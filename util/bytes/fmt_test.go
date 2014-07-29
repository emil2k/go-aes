package bytes

import (
	"testing"
)

func TestByteString(t *testing.T) {
	b := byte(0x8A)
	bs := "8a : 10001010"
	if out := ByteString(b); out != bs {
		t.Errorf("Binary string failed with %s", out)
	}
}
