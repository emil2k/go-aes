package ctr

import (
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

// processCore synchronously process buffer blocks.
func (c *Counter) processCore() {
	for i := int64(0); i < c.NBuffers(); i++ {
		c.processBuffer()
	}
}

// processBuffer runs the counter mode on a buffer block, when done it flushes the buffer to output.
// Blocks inside the buffer block are processed asynchronously on separate goroutines but processing
// of each buffer block must be done in synchronous fashion.
func (c *Counter) processBuffer() {
	c.DebugLog.Println(runtime.NumCPU(), "number of CPUs")
	sem := make(chan int, runtime.NumCPU())                // controls goroutine allocation
	results := make(chan *blockPayload, resultsBufferSize) // collects individual completed results
	var dcount int64 = 0                                   // keep track of dispatched block processing jobs
	var rcount int64 = 0                                   // count of results received
Loop:
	for {
		select {
		case sem <- 1:
			if i := c.i + dcount; dcount < int64(modes.NBufferBlocks) && i < c.NBlocks() {
				go func(b *blockPayload) {
					processBlock(b)
					results <- b
					<-sem
				}(c.newBlockPayload(i, c.Ck))
				dcount++
			}
		case b := <-results:
			c.PutBlock(b.i, b.out)
			rcount++
			if i := c.i + rcount; rcount == int64(modes.NBufferBlocks) || i == c.NBlocks() {
				break Loop
			}
		}
	}
	c.i += rcount // iterate index by number processed
	c.FlushOutBuffer()
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
	cc := b.cipher.Encrypt(b.cb, b.ck) // cipher text from encrypting cipher block
	b.out = make([]byte, len(b.in))
	for i, v := range b.in {
		b.out[i] = v ^ cc[i]
	}
}

// Encrypt encrypts the input using CTR mode
func (c *Counter) Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, false)
	c.processCore()
}

// Decrypt decrypts the input using CTR mode
func (c *Counter) Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, true)
	c.processCore()
}

// getCounterBlock gets the ith counter 16 byte block copies the data into a slice with a new underlying array.
// The first 8 bytes of the block are the nonce the last 8 bytes representing the count.
func (c *Counter) getCounterBlock(i int64) []byte {
	t := make([]byte, 0)
	t = append(t, c.nonce...)
	t = append(t, bytes.EncodeIntToBytes(i)...)
	return t
}
