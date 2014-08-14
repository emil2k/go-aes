package cipher

import (
	"io/ioutil"
	"log"

	"github.com/emil2k/go-aes/key"
	"github.com/emil2k/go-aes/state"
)

type CipherKeySize int

const (
	CK128 CipherKeySize = 128
	CK192 CipherKeySize = 192
	CK256 CipherKeySize = 256
)

// CipherFactory is a function that creates a new Cipher instance
type CipherFactory func() *Cipher

// Cipher keeps the state of encyption or decryption
type Cipher struct {
	key       *key.Key     // keeps the state of the key as it is expanded
	state     *state.State // keeps the current state of encryption
	nk        int          // the number of bytes in the cipher key
	nr        int          // the number of rounds of encyption
	r         int          // keeps track of the current round
	isDecrypt bool         // whether decrypting, affects round key iteration
	ErrorLog  *log.Logger  // log for errors
	InfoLog   *log.Logger  // log for regular progress information, non-verbose
	DebugLog  *log.Logger  // log for debug information, verbose
}

// NewCipher constructs a new cipher loading the initial state with the input
func NewCipher(ck CipherKeySize) *Cipher {
	var nk, nr int
	switch ck {
	case CK128:
		nk, nr = 4, 10
	case CK192:
		nk, nr = 6, 12
	case CK256:
		nk, nr = 8, 14
	default:
		panic("invalid cipher key size selected")
	}
	return &Cipher{
		nk:       nk,
		nr:       nr,
		ErrorLog: log.New(ioutil.Discard, "", 0),
		InfoLog:  log.New(ioutil.Discard, "", 0),
		DebugLog: log.New(ioutil.Discard, "", 0),
	}
}

// initCipher initializes the cipher either for encryption or decryption
func (c *Cipher) initCipher(in state.State, ck []byte, isDecrypt bool) {
	c.state = &in
	c.InfoLog.Println(c.state, "input")
	c.key = key.NewKey(c.nk, ck)
	c.r = 0
	c.isDecrypt = isDecrypt
}

// Encrypt configures a cipher and runs an encryption on the input
func (c *Cipher) Encrypt(in state.State, ck []byte) state.State {
	c.initCipher(in, ck, false)
	c.AddRoundKey()
	for c.r <= c.nr {
		c.state.Sub()
		c.state.Shift()
		if c.r%c.nr != 0 { // no mix on last round
			c.state.Mix()
		}
		c.AddRoundKey()
	}
	c.InfoLog.Println(c.state, "encrypted")
	return *c.state
}

// Decrypt configures the cipher and runs a decryption on the cipher text
func (c *Cipher) Decrypt(in state.State, ck []byte) state.State {
	c.initCipher(in, ck, true)
	c.AddRoundKey()
	for c.r <= c.nr {
		if c.r != 1 { // don't inverse mix on first round
			c.state.InvMix()
		}
		c.state.InvShift()
		c.state.InvSub()
		c.AddRoundKey()
	}
	c.InfoLog.Println(c.state, "decrypted")
	return *c.state
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
	c.state.Xor(*rk)
	c.r++ // iterate round
}

// GetRoundKey gets the ith round key as a state instance, expands the key if necessary.
func (c *Cipher) GetRoundKey(i int) *state.State {
	for c.key.NWords() < (i+1)*4 { // need to expand the key, 4 word per state
		c.key.Expand()
	}
	return state.NewStateFromWords(c.key.GetWordSlice(i*4, (i+1)*4))
}
