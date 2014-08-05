package bytes

// Split32 splits a 32 bit intiger into 4 bytes, returning them starting with the
// least signficant byte.
func Split32(in uint32) (b0, b1, b2, b3 byte) {
	b0 = byte(in & 0xFF)
	b1 = byte((in & uint32(0xFF<<8)) >> 8)
	b2 = byte((in & uint32(0xFF<<16)) >> 16)
	b3 = byte((in & uint32(0xFF<<24)) >> 24)
	return
}

// Join32 joints a 4 byte slice into an integer.
func Join32(in []byte) uint32 {
	return uint32(in[0]) + uint32(in[1])<<8 + uint32(in[2])<<16 + uint32(in[3])<<24
}
