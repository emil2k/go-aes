package bytes

import ()

// EncodeIntToBytes gets a byte slice representation of the number.
// Slice will have a length of 8 to fit a 64 bit number and store bytes
// in little endian order.
func EncodeIntToBytes(n uint64) []byte {
	t := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		t[i] = getIntByte(n, i)
	}
	return t
}

// DecodeIntFromBytes gets an integer from a byte slice assumes byte slice
// ordered in little endian order.
func DecodeIntFromBytes(b []byte) uint64 {
	var t uint64
	for i := uint(0); i < uint(len(b)); i++ {
		t += uint64(b[i]) << (i * 8)
	}
	return t
}

// getIntByte gets the ith byte in little endian order of the passed integer.
func getIntByte(n uint64, i uint) byte {
	return byte(n >> (8 * i))
}
