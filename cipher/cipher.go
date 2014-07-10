package cipher

import (
	"github.com/emil2k/aes/key"
	"github.com/emil2k/aes/state"
)

// Cipher keeps the state of encyption of decryption
type Cipher struct {
	key   key.Key     // keeps the state of the key as it is expanded
	state state.State // keeps the current state of encryption
	nr    int         // the number of rounds of encyption
	r     int         // keeps track of the current round
}

// NewCipher constructs a new cipher loading the initial state with the input
func NewCipher(nk int, nr int, in []byte, ck []byte) *Cipher {
	return &Cipher{
		key:   *key.NewKey(nk, ck),
		state: state.State(in),
		nr:    nr,
	}
}

// String provides a string representation of the currest cipher state
func (c Cipher) String() string {
	return c.state.String()
}

// AddRoundKey xors the current round key to the cipher's state
func (c *Cipher) AddRoundKey() {
	rk := c.GetRoundKey()
	c.state.Xor(rk)
}

// GetRoundKey gets the current round key, expands the key if necessary
func (c *Cipher) GetRoundKey() []byte {
	out := make([]byte, 16)
	if len(c.key.Data) < (c.r+1)*16 { // need to expand the key
		c.key.Expand()
	}
	copy(out, c.key.Data[c.r*16:(c.r+1)*16])
	c.r++ // iterate round
	return out
}

func Encrypt(nk int, nr int, in []byte, ck []byte) []byte {
	c := NewCipher(nk, nr, in, ck)
	c.AddRoundKey()
	for c.r < c.nr {
		c.state.Sub()
		c.state.Shift()
		c.state.Mix()
		c.AddRoundKey()
	}
	// Don't mix columns on the last round
	c.state.Sub()
	c.state.Shift()
	c.AddRoundKey()
	return c.state
}

func Decrypt(c []byte, ck []byte) []byte {
	// TODO
	return []byte{}
}
