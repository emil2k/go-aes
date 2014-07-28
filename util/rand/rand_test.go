package rand

import "bytes"
import "testing"

func TestGetRand(t *testing.T) {
	rand := GetRand(3)
	if len(rand) != 3 {
		t.Errorf("Random byte slice length is wrong %d", len(rand))
	}
	if z := make([]byte, 3); bytes.Equal(z, rand) {
		t.Errorf("Random bytes are all zeroes")
	}
}
