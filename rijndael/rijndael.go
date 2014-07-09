package rijndael

import "fmt"

// rjnum represents a number in the Rijndael finite field
type rjnum byte

// String provides a binary representation of a Rijndael number
func (b rjnum) String() string {
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

// Add adds two byte length polynomials in the GF(2^8)
func Add(a, b rjnum) rjnum {
	return a ^ b
}

// Sub subtracts two byte length polynomials in the GF(2^8)
func Sub(a, b rjnum) rjnum {
	return a ^ b
}

// Mul multiplies two byte length polynomials in the Rijndael finite field
// reduced by the 0x11b polynomial
func Mul(a, b rjnum) rjnum {
	var p rjnum
	for i := 0; i < 8; i++ {
		if b&0x01 == 1 {
			p ^= a
		}
		b >>= 1
		carry := a&0x80 == 1<<7
		a <<= 1
		if carry {
			a ^= 0x1b
		}
	}
	return p
}
