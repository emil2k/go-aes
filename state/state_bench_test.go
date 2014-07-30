package state

import (
	"testing"
)

func newState() *State {
	state := State([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	return &state
}

func BenchmarkString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().String()
	}
}

func BenchmarkSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().Sub()
	}
}

func BenchmarkInvSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().InvSub()
	}
}

func BenchmarkShift(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().Shift()
	}
}

func BenchmarkInvShift(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().InvShift()
	}
}

func BenchmarkMix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().Mix()
	}
}

func BenchmarkInvMix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().InvMix()
	}
}

func BenchmarkMixCol(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().MixCol(1)
	}
}

func BenchmarkInvMixCol(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().InvMixCol(1)
	}
}

func BenchmarkXor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().Xor(*newState())
	}
}

func BenchmarkGetCol(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().GetCol(1)
	}
}

func BenchmarkSetCol(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().SetCol(1, []byte{0x01, 0x02, 0x03, 0x04})
	}
}

func BenchmarkGetRow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().GetRow(1)
	}
}

func BenchmarkSetRow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().SetRow(1, []byte{0x01, 0x02, 0x03, 0x04})
	}
}
