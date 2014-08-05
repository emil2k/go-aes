package bytes

import (
	"fmt"
)

// BinaryString provides a binary representation of a number.
func BinaryString(b uint64) string {
	var out string = fmt.Sprintf("%x : ", b)
	var i uint8
	for i = 0; i < 64; i++ {
		if 0x01 == (b>>(63-i))&0x01 {
			out += "1"
		} else {
			out += "0"
		}
	}
	return out
}
