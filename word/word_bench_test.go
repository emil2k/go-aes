package word

import (
	"testing"
)

func newWord() Word {
	return Word([]byte{0xC3, 0x89, 0xAF, 0xF8})
}

func BenchmarkWordString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().String()
	}
}

func BenchmarkWordRot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Rot(1)
	}
}

func BenchmarkWordInvRot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().InvRot(1)
	}
}

func BenchmarkWordSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Sub()
	}
}

func BenchmarkWordInvSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().InvSub()
	}
}

func BenchmarkWordXor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Xor(newWord())
	}
}
