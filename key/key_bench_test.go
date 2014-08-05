package key

import (
	"github.com/emil2k/go-aes/util/rand"
	"testing"
)

func BenchmarkExpand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		k := NewKey(4, rand.GetRand(16))
		b.StartTimer()
		for i := 0; i < 10; i++ {
			k.Expand()
		}
	}
}

func BenchmarkString(b *testing.B) {
	k := NewKey(4, rand.GetRand(16))
	for i := 0; i < 10; i++ {
		k.Expand()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.String()
	}
}

func BenchmarkGetWord(b *testing.B) {
	k := NewKey(4, rand.GetRand(16))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.GetWord(1)
	}
}
