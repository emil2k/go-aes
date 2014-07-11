package cipher

import (
	"github.com/emil2k/go-aes/key"
	"github.com/emil2k/go-aes/state"
)

// Cipher keeps the state of encyption or decryption
type Cipher struct {
	key       key.Key     // keeps the state of the key as it is expanded
	state     state.State // keeps the current state of encryption
	nr        int         // the number of rounds of encyption
	r         int         // keeps track of the current round
	isDecrypt bool        // whether decrypting, affects round key iteration
}

// NewCipher constructs a new cipher loading the initial state with the input
func NewCipher(nk int, nr int, in []byte, ck []byte, isDecrypt bool) *Cipher {
	return &Cipher{
		key:       *key.NewKey(nk, ck),
		state:     state.State(in),
		nr:        nr,
		isDecrypt: isDecrypt,
	}
}

// String provides a string representation of the currest cipher state
func (c Cipher) String() string {
	return c.state.String()
}

// AddRoundKey xors the current round key to the cipher's state
func (c *Cipher) AddRoundKey() {
	var i int
	if c.isDecrypt {
		i = c.nr - c.r // reverse iteration
	} else {
		i = c.r
	}
	rk := c.GetRoundKey(i)
	c.state.Xor(rk)
	c.r++ // iterate round
}

// GetRoundKey gets the ith round key, expands the key if necessary
func (c *Cipher) GetRoundKey(i int) []byte {
	out := make([]byte, 16)
	for len(c.key.Data) < (i+1)*16 { // need to expand the key
		c.key.Expand()
	}
	copy(out, c.key.Data[i*16:(i+1)*16])
	return out
}

// Encrypt configures a cipher and runs an encryption on the input
func Encrypt(nk int, nr int, in []byte, ck []byte) []byte {
	c := NewCipher(nk, nr, in, ck, false)
	c.AddRoundKey()
	for c.r < c.nr {
		c.state.Sub()
		c.state.Shift()
		c.state.Mix()
		c.AddRoundKey()
	}
	c.state.Sub()
	c.state.Shift() // no mix on last round
	c.AddRoundKey()
	return c.state
}

// Decrypt configures the cipher and runs a decryption on the cipher text
func Decrypt(nk int, nr int, ct []byte, ck []byte) []byte {
	c := NewCipher(nk, nr, ct, ck, true)
	c.AddRoundKey()
	c.state.InvShift()
	c.state.InvSub()
	for c.r < c.nr {
		c.AddRoundKey()
		c.state.InvMix()
		c.state.InvShift()
		c.state.InvSub()
	}
	c.AddRoundKey()
	return c.state
}
