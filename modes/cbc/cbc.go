package cbc

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"io"
)

// Chain represents the state of a cipher-block chaining process.
type Chain struct {
	modes.Mode
	last []byte // last cipher text or initilization vector
}

// NewChain creates a new chain instance with the given CipherFactory instance.
func NewChain(cf cipher.CipherFactory) *Chain {
	return &Chain{
		Mode: *modes.NewMode(cf),
	}
}

// initChain initializes chain instance to run an encryption or decryption.
func (c *Chain) initChain(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte, isDecrypt bool) {
	c.InitMode(offset, size, in, out, ck, isDecrypt)
	c.last = nonce
}

// Encrypt runs the encryption process.
func (c *Chain) Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, false)
	bc := c.Cf()
	var i int64
	for i = 0; i < c.NBlocks(); i++ {
		state := c.GetBlock(i)
		for i, _ := range state {
			state[i] ^= c.last[i]
		}
		state = bc.Encrypt(state, c.Ck)
		c.PutBlock(i, state)
		c.last = state
	}
}

// Decrypt runs the decryption process
func (c *Chain) Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, true)
	bc := c.Cf()
	var i int64
	for i = 0; i < c.NBlocks(); i++ {
		ct := c.GetBlock(i) // block of cipher text
		state := bc.Decrypt(ct, c.Ck)
		for i, _ := range state {
			state[i] ^= c.last[i]
		}
		c.PutBlock(i, state)
		c.last = ct
	}
}
