package key

import "fmt"
import "github.com/emil2k/go-aes/word"

// Key represents a key and maintains the state of while a cipher key is expanded
type Key struct {
	i    int    // keeps track of iteration during key expansion
	nk   int    // number of 4 byte column in the key, i.e. 4 for 128 bit
	Data []byte // byte representing the key
}

// String provides a string representation of a Key
func (k Key) String() string {
	out := fmt.Sprintf("Key with Nk %d on iteration %d, with %d bytes :\n", k.nk, k.i, len(k.Data))
	for i := 0; i < len(k.Data)/4; i++ {
		out += fmt.Sprintf("\nw%d : ", i)
		out += k.GetWord(i).String()
	}
	out += "\n"
	return out
}

// NewKey constructs a Key object by seeding it with a cipher key and setting Nk
func NewKey(nk int, seed []byte) *Key {
	k := Key{i: 0, nk: nk, Data: make([]byte, len(seed))}
	copy(k.Data, seed) // seed the key
	k.i = len(seed) / 4
	return &k
}

// Expand the key by Nk * 4 bytes
func (k *Key) Expand() {
	for start := k.i; k.i == start || k.i%k.nk != 0; k.i++ {
		t := k.GetWord(k.i - 1)
		if k.i%k.nk == 0 {
			t.Rot(1)
			t.Sub()
			rcon := word.Word([]byte{Rcon(k.i / k.nk)})
			t.Xor(rcon)
		} else if k.nk == 8 && k.i%k.nk == 4 { //  extra step for 256 bit keys
			t.Sub()
		}
		lr := k.GetWord(k.i - k.nk)
		t.Xor(lr)
		k.Data = append(k.Data, t...)
	}
}

// GetWord gets the word at the index i in the key
// copies word into a slice with a new underlying array
func (k *Key) GetWord(i int) word.Word {
	w := make([]byte, 4)
	copy(w, k.Data[i*4:i*4+4])
	return word.Word(w)
}

// Rcon returns the exponential of 2 to the i-1 in the Rijndael finitie field
func Rcon(i int) byte {
	return rcon[i]
}

var rcon = [256]byte{
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d}
