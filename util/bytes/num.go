package bytes

// EncodeIntToBytes gets a byte slice representation of the number.
// Slice will have a length of 8 to fit a 64 bit number and store bytes
// in big endian order.
func EncodeIntToBytes(n int64) []byte {
	t := make([]byte, 8)
	var i uint
	for i = 0; i < 8; i++ {
		t[7-i] = getIntByte(n, i)
	}
	return t
}

// getIntByte gets the ith byte in little endian order of the passed integer.
func getIntByte(n int64, i uint) byte {
	return byte(n >> (8 * i))
}
