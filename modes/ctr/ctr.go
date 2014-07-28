package ctr

import (
	"encoding/hex"
	"fmt"
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"io"
	"runtime"
)

// Counter keeps track of the state of a counter cipher mode
// used for encryption or decryption
type Counter struct {
	modes.Mode
	i     int    // keeps track of the counter
	nonce []byte // initialization vector
}

// NewCounter constructs a new counter instance with logs that discard output
func NewCounter(cf cipher.CipherFactory) *Counter {
	return &Counter{
		Mode: *modes.NewMode(cf),
	}
}

// initCounter initializes a counter either for encryption or decryption
func (c *Counter) initCounter(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte, isDecrypt bool) {
	c.InitMode(offset, size, in, out, ck, isDecrypt)
	c.i = 0
	c.nonce = nonce
}

// processCounterCore runs the core of the counter mode each block is run
// on separate goroutines and gathered together at the end
func (c *Counter) processCounterCore() {
	c.DebugLog.Println(runtime.NumCPU(), "number of CPUs")
	sem := make(chan int, runtime.NumCPU())          // controls goroutine allocation
	results := make(chan *blockPayload, c.NBlocks()) // collects individual completed results
	for int64(c.i) < c.NBlocks() {
		sem <- 1
		go func(b *blockPayload) {
			c.DebugLog.Println("running block", b.i)
			processBlock(b)
			results <- b
			<-sem
		}(c.newBlockPayload(c.i, c.Ck))
		c.i++
	}
	// Put results together
	for i := 0; int64(i) < c.NBlocks(); i++ {
		b := <-results
		c.PutBlock(b.i, b.out)
	}
}

// blockPayload keeps the state of a block while it is being processed
// in a goroutine and is then sent back as the result over a channel
type blockPayload struct {
	cipher *cipher.Cipher // block cipher used
	i      int            // block number
	in     []byte         // input block
	out    []byte         // output of block
	ck     []byte         // cipher key
	cb     []byte         // counter block
}

// newBlockPayload creates a new instance of a block payload
func (c *Counter) newBlockPayload(i int, ck []byte) *blockPayload {
	return &blockPayload{
		i:      i,
		cipher: c.Cf(),
		in:     c.GetBlock(i),
		out:    make([]byte, 0),
		ck:     ck,
		cb:     c.getCounterBlock(i),
	}
}

// processBlock processes an individual block payload
func processBlock(b *blockPayload) {
	b.cipher.DebugLog.Println("process block", b.i, hex.EncodeToString(b.in))
	cc := b.cipher.Encrypt(b.cb, b.ck) // cipher text from encrypting cipher block
	b.out = make([]byte, len(b.in))
	for i, v := range b.in {
		b.out[i] = v ^ cc[i]
	}
}

// Encrypt encrypts the input using CTR mode
func (c *Counter) Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, false)
	c.processCounterCore()
}

// Decrypt decrypts the input using CTR mode
func (c *Counter) Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, true)
	c.processCounterCore()
}

// getCounterBlock gets the ith counter 16 byte block copies the data into a
// slice with a new underlying array.
// The first 8 bytes of the block are the nonce the last 8 bytes consist of all
// zeroes with the last byte being the count will panic if surpasses maximum count of 1 << 8
func (c *Counter) getCounterBlock(i int) []byte {
	if i >= 1<<8 {
		panic(fmt.Sprintf("over maximum counter %d", 1<<8))
	}
	t := make([]byte, 16)
	copy(t, c.nonce)
	t[15] = byte(i) // set the last byte to the counter
	return t
}
