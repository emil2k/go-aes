package cipher

import (
	"io/ioutil"
	"log"

	"github.com/emil2k/go-aes/key"
	"github.com/emil2k/go-aes/state"
)

// CipherFactory is a function that creates a new Cipher instance
type CipherFactory func() *Cipher

// Cipher keeps the state of encyption or decryption
type Cipher struct {
	key       key.Key     // keeps the state of the key as it is expanded
	state     state.State // keeps the current state of encryption
	nk        int         // the number of bytes in the cipher key
	nr        int         // the number of rounds of encyption
	r         int         // keeps track of the current round
	isDecrypt bool        // whether decrypting, affects round key iteration
	ErrorLog  *log.Logger // log for errors
	InfoLog   *log.Logger // log for regular progress information, non-verbose
	DebugLog  *log.Logger // log for debug information, verbose
}

// NewCipher constructs a new cipher loading the initial state with the input
func NewCipher(nk int, nr int) *Cipher {
	return &Cipher{
		nk:       nk,
		nr:       nr,
		ErrorLog: log.New(ioutil.Discard, "", 0),
		InfoLog:  log.New(ioutil.Discard, "", 0),
		DebugLog: log.New(ioutil.Discard, "", 0),
	}
}

// initCipher initializes the cipher either for encryption or decryption
func (c *Cipher) initCipher(in []byte, ck []byte, isDecrypt bool) {
	c.state = state.State(in)
	c.key = *key.NewKey(c.nk, ck)
	c.r = 0
	c.isDecrypt = isDecrypt
	if c.isDecrypt {
		c.DebugLog.Println("begin decryption")
	} else {
		c.DebugLog.Println("begin encryption")
	}
	c.DebugLog.Println(c.nk, "nk, bytes in key")
	c.DebugLog.Println(c.nr, "nr, number of rounds")
	c.DebugLog.Println(c.state, "initial state")
	c.DebugLog.Println(c.key, "initial state of key")
}

// Encrypt configures a cipher and runs an encryption on the input
func (c *Cipher) Encrypt(in []byte, ck []byte) []byte {
	c.InfoLog.Println(state.State(in), "input")
	c.InfoLog.Println(state.State(ck), "cipher key")
	c.initCipher(in, ck, false)
	c.AddRoundKey()
	for c.r <= c.nr {
		c.DebugLog.Println(c.state, "begin round")
		c.state.Sub()
		c.DebugLog.Println(c.state, "subsituted bytes")
		c.state.Shift()
		c.DebugLog.Println(c.state, "shifted bytes")
		if c.r%c.nr != 0 { // no mix on last round
			c.state.Mix()
			c.DebugLog.Println(c.state, "mixed columns")
		}
		c.AddRoundKey()
	}
	c.InfoLog.Println(c.state, "encrypted")
	return c.state
}

// Decrypt configures the cipher and runs a decryption on the cipher text
func (c *Cipher) Decrypt(in []byte, ck []byte) []byte {
	c.InfoLog.Println(state.State(in), "input")
	c.InfoLog.Println(state.State(ck), "cipher key")
	c.initCipher(in, ck, true)
	c.AddRoundKey()
	for c.r <= c.nr {
		c.DebugLog.Println(c.state, "begin round")
		if c.r != 1 { // don't inverse mix on first round
			c.state.InvMix()
			c.DebugLog.Println(c.state, "inversed mixed columns")
		}
		c.state.InvShift()
		c.DebugLog.Println(c.state, "inversed shifted bytes")
		c.state.InvSub()
		c.DebugLog.Println(c.state, "inversed substituted bytes")
		c.AddRoundKey()
	}
	c.InfoLog.Println(c.state, "decrypted")
	return c.state
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
	c.DebugLog.Println(state.State(rk), "round key #", i)
	c.DebugLog.Println(c.state, "round key xored")
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
