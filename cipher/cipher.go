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

// String provides a string representation of the currest cipher state
func (c *Cipher) String() string {
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

func Encrypt(in []byte, ck []byte) []byte {
	// TODO
	return []byte{}
}

func Decrypt(c []byte, ck []byte) []byte {
	// TODO
	return []byte{}
}
