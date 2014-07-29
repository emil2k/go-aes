package ctr

import (
	"encoding/hex"
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/util/bytes"
	"io"
	"runtime"
)

const resultsBufferSize int = 30 // buffer size of channel receiving results

// Counter keeps track of the state of a counter cipher mode
// used for encryption or decryption
type Counter struct {
	modes.Mode
	i     int64  // keeps track of the counter
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
	sem := make(chan int, runtime.NumCPU())                // controls goroutine allocation
	results := make(chan *blockPayload, resultsBufferSize) // collects individual completed results
	var rcount int64 = 0                                   // count of results received
Loop:
	for {
		select {
		case sem <- 1:
			c.DebugLog.Println("select, process block", c.i)
			if c.i < c.NBlocks() {
				go func(b *blockPayload) {
					c.DebugLog.Println("running block", b.i)
					processBlock(b)
					results <- b
					<-sem
				}(c.newBlockPayload(c.i, c.Ck))
				c.i++
			}
		case b := <-results:
			c.DebugLog.Println("select, put result - buffered results", len(results))
			c.PutBlock(b.i, b.out)
			rcount++
			if rcount == c.NBlocks() {
				c.DebugLog.Println("received all results break loop")
				break Loop
			}
		}
	}
}

// blockPayload keeps the state of a block while it is being processed
// in a goroutine and is then sent back as the result over a channel
type blockPayload struct {
	cipher *cipher.Cipher // block cipher used
	i      int64          // block number
	in     []byte         // input block
	out    []byte         // output of block
	ck     []byte         // cipher key
	cb     []byte         // counter block
}

// newBlockPayload creates a new instance of a block payload
func (c *Counter) newBlockPayload(i int64, ck []byte) *blockPayload {
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

// getCounterBlock gets the ith counter 16 byte block copies the data into a slice with a new underlying array.
// The first 8 bytes of the block are the nonce the last 8 bytes representing the count.
func (c *Counter) getCounterBlock(i int64) []byte {
	t := make([]byte, 0)
	t = append(t, c.nonce...)
	t = append(t, bytes.EncodeIntToBytes(i)...)
	return t
}
