package key

import (
	"github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/word"
	rj "github.com/emil2k/go-math/rijndael"
)

// Key represents a key and maintains the state of while a cipher key is expanded
type Key struct {
	i     int         // keeps track of iteration during key expansion
	nk    int         // number of 4 byte column in the key, i.e. 4 for 128 bit
	words []word.Word // words that compromise key
}

// String provides a string representation of a Key.
// Key is represented in little endian order with word index increasing from right to left.
func (k Key) String() string {
	var out string
	for _, w := range k.words {
		out = w.String() + out
	}
	return out
}

// NewKey constructs a Key object by seeding it with a cipher key and setting Nk
func NewKey(nk int, seed []byte) *Key {
	k := Key{i: 0, nk: nk, words: make([]word.Word, 0)}
	// Initiate key with seed
	for j := 0; j < len(seed)/4; j++ {
		k.words = append(k.words, word.Word(bytes.Join32(seed[4*j:4*(j+1)])))
		k.i++
	}
	return &k
}

// Expand the key by Nk * 4 bytes
func (k *Key) Expand() {
	for start := k.i; k.i == start || k.i%k.nk != 0; k.i++ {
		t := k.GetWord(k.i - 1)
		if k.i%k.nk == 0 {
			t.Rot()
			t.Sub()
			rcon := word.Word(rj.Rcon(k.i / k.nk))
			t.Xor(rcon)
		} else if k.nk == 8 && k.i%k.nk == 4 { //  extra step for 256 bit keys
			t.Sub()
		}
		lr := k.GetWord(k.i - k.nk)
		t.Xor(lr)
		k.words = append(k.words, t)
	}
}

// GetWord gets the word at the index i in the key
// copies word into a slice with a new underlying array
func (k *Key) GetWord(i int) word.Word {
	return k.words[i]
}

// GetWordSlice returns a word slice from the start index to the end index ( excluding ).
func (k *Key) GetWordSlice(start, end int) []word.Word {
	return k.words[start:end]
}

// NWords returns the number of words the key contains.
func (k *Key) NWords() int {
	return len(k.words)
}
