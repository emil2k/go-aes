package cbc

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/state"
	"io"
)

// Chain represents the state of a cipher-block chaining process.
type Chain struct {
	modes.Mode
	last   state.State    // last cipher text or initilization vector
	cipher *cipher.Cipher // block cipher instance
}

// NewChain creates a new chain instance with the given CipherFactory instance.
func NewChain(cf cipher.CipherFactory) *Chain {
	return &Chain{
		Mode: *modes.NewMode(cf),
	}
}

// initChain initializes chain instance to run an encryption or decryption.
func (c *Chain) initChain(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte, isDecrypt bool) {
	c.InitMode(offset, size, in, out, ck, isDecrypt)
	c.last = *state.NewStateFromBytes(nonce)
	c.cipher = c.Cf()
}

// processBlocks process all blocks, repeatedly flushing buffers as they fill up.
func (c *Chain) processBlocks(process func(i uint64)) {
	// Process one buffer block at a time
	for j := uint64(0); j < c.NBuffers(); j++ {
		c.FillInBuffer()
		// Process each block in the buffer block
		for k := uint64(0); k < modes.NBufferBlocks; k++ {
			i := k + j*modes.NBufferBlocks
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
func (c *Chain) encryptBlock(i uint64) {
	c.last.Xor(c.GetBlock(i))
	c.last = c.cipher.Encrypt(c.last, c.Ck)
	c.PutBlock(i, c.last)
}

// decryptBlock decrypts the ith block, getting it from the input buffer then putting it
// into the output buffer after decryption. Should be called iteratively on each block.
func (c *Chain) decryptBlock(i uint64) {
	b := c.GetBlock(i)
	c.last.Xor(c.cipher.Decrypt(b, c.Ck))
	c.PutBlock(i, c.last)
	c.last = b
}

// Encrypt runs the encryption process.
func (c *Chain) Encrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, false)
	c.processBlocks(c.encryptBlock)
}

// Decrypt runs the decryption process
func (c *Chain) Decrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initChain(offset, size, in, out, ck, nonce, true)
	c.processBlocks(c.decryptBlock)
}
