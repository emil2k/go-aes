package word

import (
	"testing"
)

func BenchmarkString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().String()
	}
}

func BenchmarkRot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Rot()
	}
}

func BenchmarkInvRot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().InvRot()
	}
}

func BenchmarkSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Sub()
	}
}

func BenchmarkInvSub(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().InvSub()
	}
}

func BenchmarkXor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newWord().Xor(*newWord())
	}
}
