package key

import (
	"github.com/emil2k/go-aes/word"
	"testing"
)

func TestKeyString(t *testing.T) {
	ck := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c} // cipher key
	k := NewKey(4, ck)
	out := "3c4fcf098815f7aba6d2ae2816157e2b"
	if x := k.String(); x != out {
		t.Errorf("Key stringify failed with %s", x)
	}
}

func TestGetWord(t *testing.T) {
	ck := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c} // cipher key
	k := NewKey(4, ck)
	if w0 := k.GetWord(0); w0 != 0x16157e2b {
		t.Errorf("Get word failed with %v", w0)
	}
	if w1 := k.GetWord(1); w1 != 0xa6d2ae28 {
		t.Errorf("Get word failed with %v", w1)
	}
}

func TestGetWordSlice(t *testing.T) {
	ck := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c} // cipher key
	k := NewKey(4, ck)
	if w := k.GetWordSlice(1, 3); len(w) != 2 {
		t.Errorf("Get word slice failed with wrong length")
	} else if w[0] != k.GetWord(1) || w[1] != k.GetWord(2) { // assumes get word tested
		t.Errorf("Get word slice failed components don't match get word")
	}
}

func TestNWords(t *testing.T) {
	ck := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c} // cipher key
	k := NewKey(4, ck)
	if k.NWords() != 4 {
		t.Errorf("Getting number of words failed")
	}
}

// assertWord asserts that the ith word in a key equals the passed byte slice
func assertWord(t *testing.T, k *Key, i int, out word.Word) {
	if w := k.GetWord(i); w != out {
		t.Errorf("Word assertion failed with %v at %d, wanted %v.", w, i, out)
	}
}

func TestExpand128(t *testing.T) {
	ck := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c} // cipher key
	k := NewKey(4, ck)
	k.Expand()
	assertWord(t, k, 4, word.Word(0x17fefaa0))
	k.Expand()
	assertWord(t, k, 11, word.Word(0x7ff65973))
}

func TestExpand192(t *testing.T) {
	ck := []byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b}
	k := NewKey(6, ck)
	k.Expand()
	assertWord(t, k, 6, word.Word(0xf7910cfe))
	k.Expand()
	assertWord(t, k, 17, word.Word(0x865309bb))
}

func TestExpand256(t *testing.T) {
	ck := []byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}
	k := NewKey(8, ck)
	k.Expand()
	assertWord(t, k, 14, word.Word(0x6e8449be))
	k.Expand()
	assertWord(t, k, 21, word.Word(0x47a67826))
}
