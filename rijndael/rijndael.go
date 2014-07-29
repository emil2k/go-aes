package rijndael

// Add adds two byte length polynomials in the GF(2^8)
func Add(a, b byte) byte {
	return a ^ b
}

// Sum sums multiple byte length polynomials together in GF(2^8)
func Sum(args ...byte) byte {
	var sum byte
	for _, v := range args {
		sum = Add(sum, v)
	}
	return sum
}

// Sub subtracts two byte length polynomials in the GF(2^8)
func Sub(a, b byte) byte {
	return a ^ b
}

// Mul multiplies two byte length polynomials in the Rijndael finite field
// reduced by the 0x11b polynomial
func Mul(a, b byte) byte {
	var p byte
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
