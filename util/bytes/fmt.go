package bytes

import (
	"fmt"
)

// ByteString provides a binary representation of a byte, utility for debugging
func ByteString(b byte) string {
	var out string = fmt.Sprintf("%x : ", byte(b))
	var i uint8
	for i = 0; i < 8; i++ {
		if 0x01 == (b>>(7-i))&0x01 {
			out += "1"
		} else {
			out += "0"
		}
	}
	return out
}
