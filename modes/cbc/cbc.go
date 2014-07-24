package cbc

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
)

// Chain represents the state of a cipher-block chaining process
type Chain struct {
	modes.Mode
	last []byte // last cipher text or initilization vector
}

// NewChain creates a new chain instance with the given CipherFactory instance
func NewChain(cf cipher.CipherFactory) *Chain {
	return &Chain{
		Mode: *modes.NewMode(cf),
	}
}

// initChain initializes chain istance to run an encryption or decryption
// `in` represents the input into the function can either the plaintext or
// ciphertext depending on whether encrypting or decrypting
func (c *Chain) initChain(in []byte, ck []byte, nonce []byte, isDecrypt bool) {
	c.InitMode(in, ck, isDecrypt)
	c.last = nonce
}

// Encrypt runs the encryption process
func (c *Chain) Encrypt(in, ck, nonce []byte) []byte {
	c.initChain(in, ck, nonce, false)
	c.AddPadding()
	bc := c.Cf()
	for i := 0; i < c.NBlocks(); i++ {
		state := c.GetBlock(i)
		for i, _ := range state {
			state[i] ^= c.last[i]
		}
		state = bc.Encrypt(state, c.Ck)
		c.PutBlock(i, state)
		c.last = state
	}
	return c.Out
}

// Decrypt runs the decryption process
func (c *Chain) Decrypt(in, ck, nonce []byte) []byte {
	c.initChain(in, ck, nonce, true)
	bc := c.Cf()
	for i := 0; i < c.NBlocks(); i++ {
		ct := c.GetBlock(i) // block of cipher text
		state := bc.Decrypt(ct, c.Ck)
		for i, _ := range state {
			state[i] ^= c.last[i]
		}
		c.PutBlock(i, state)
		c.last = ct
	}
	c.RemovePadding()
	return c.Out
}
