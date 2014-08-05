package state

import (
	"github.com/emil2k/go-aes/word"
	"testing"
)

func BenchmarkString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().String()
	}
}

func BenchmarkNewStateFromBytes(b *testing.B) {
	s := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewStateFromBytes(s)
	}
}

func BenchmarkNewStateFromWords(b *testing.B) {
	s := []word.Word{word.Word(0x16157e2b), word.Word(0xa6d2ae28), word.Word(0x8815f7ab), word.Word(0x3c4fcf09)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewStateFromWords(s)
	}
}

func BenchmarkGetBytes(b *testing.B) {
	s := &State{high: 0x3c4fcf098815f7ab, low: 0xa6d2ae2816157e2b}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetBytes()
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
		newState().SetCol(1, 0x01020304)
	}
}

func BenchmarkGetRow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().GetRow(1)
	}
}

func BenchmarkSetRow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newState().SetRow(1, 0x01020304)
	}
}
