package bytes

// EachByte64 performs the passed operation on each byte in the passed uint64.
func EachByte64(in uint64, op func(in byte) byte) uint64 {
	return uint64(op(byte(0xFF&in))) ^
		uint64(op(byte((0xFF<<8&in)>>8)))<<8 ^
		uint64(op(byte((0xFF<<16&in)>>16)))<<16 ^
		uint64(op(byte((0xFF<<24&in)>>24)))<<24 ^
		uint64(op(byte((0xFF<<32&in)>>32)))<<32 ^
		uint64(op(byte((0xFF<<40&in)>>40)))<<40 ^
		uint64(op(byte((0xFF<<48&in)>>48)))<<48 ^
		uint64(op(byte((0xFF<<56&in)>>56)))<<56
}

// EachByte32 performs the passed operation on each byte in the passed uint32.
func EachByte32(in uint32, op func(in byte) byte) uint32 {
	return uint32(op(byte(0xFF&in))) ^
		uint32(op(byte((0xFF<<8&in)>>8)))<<8 ^
		uint32(op(byte((0xFF<<16&in)>>16)))<<16 ^
		uint32(op(byte((0xFF<<24&in)>>24)))<<24
}
