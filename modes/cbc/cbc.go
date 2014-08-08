package cbc

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"io"
)

// Chain represents the state of a cipher-block chaining process.
type Chain struct {
	modes.Mode
	last   []byte         // last cipher text or initilization vector
	cipher *cipher.Cipher // block cipher instance
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
	c.cipher = c.Cf()
}

// processBlocks process all blocks, repeatedly flushing buffers as they fill up.
func (c *Chain) processBlocks(process func(i int64)) {
	// Process one buffer block at a time
	for j := 0; int64(j) < c.NBuffers(); j++ {
		// Process each block in the buffer block
		for k := 0; k < modes.NBufferBlocks; k++ {
			i := int64(k + j*modes.NBufferBlocks)
			if i >= c.NBlocks() {
				break
			}
			process(i) // process the buffer block
		}
		c.FlushOutBuffer()
	}
}

// encryptBlock encrypts the ith block, getting it from the input buffer then putting it
// into the output buffer after encryption. Should be called iteratively on each block.
func (c *Chain) encryptBlock(i int64) {
	state := c.GetBlock(i)
	for i, _ := range state {
		state[i] ^= c.last[i]
	}
	state = c.cipher.Encrypt(state, c.Ck)
	c.PutBlock(i, state)
	c.last = state
}

// decryptBlock decrypts the ith block, getting it from the input buffer then putting it
// into the output buffer after decryption. Should be called iteratively on each block.
func (c *Chain) decryptBlock(i int64) {
	ct := c.GetBlock(i) // block of cipher text
	state := c.cipher.Decrypt(ct, c.Ck)
	for i, _ := range state {
		state[i] ^= c.last[i]
	}
	c.PutBlock(i, state)
	c.last = ct
}

// Encrypt runs the encryption process.
func (c *Chain) Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, false)
	c.processBlocks(c.encryptBlock)
}

// Decrypt runs the decryption process
func (c *Chain) Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, true)
	c.processBlocks(c.decryptBlock)
}
