package ctr

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/state"
	"github.com/emil2k/go-aes/util/bytes"
	"io"
	"runtime"
)

const resultsBufferSize int = 30 // buffer size of channel receiving results

// Counter keeps track of the state of a counter cipher mode
// used for encryption or decryption
type Counter struct {
	modes.Mode
	i     uint64 // keeps track of the counter
	nonce uint64 // initialization vector
}

// NewCounter constructs a new counter instance with logs that discard output
func NewCounter(cf cipher.CipherFactory) *Counter {
	return &Counter{
		Mode: *modes.NewMode(cf),
	}
}

// initCounter initializes a counter either for encryption or decryption
func (c *Counter) initCounter(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte, isDecrypt bool) {
	c.InitMode(offset, size, in, out, ck, isDecrypt)
	c.i = 0
	c.nonce = bytes.DecodeIntFromBytes(nonce)
}

// processCore synchronously process buffer blocks.
func (c *Counter) processCore() {
	for i := uint64(0); i < c.NBuffers(); i++ {
		c.processBuffer()
	}
}

// processBuffer runs the counter mode on a buffer block, when done it flushes the buffer to output.
// Blocks inside the buffer block are processed asynchronously on separate goroutines but processing
// of each buffer block must be done in synchronous fashion.
func (c *Counter) processBuffer() {
	cpus := runtime.NumCPU()
	c.DebugLog.Println(cpus, "number of CPUs")
	c.DebugLog.Println(runtime.GOMAXPROCS(cpus), "previous max procs")
	sem := make(chan int, runtime.NumCPU())                // controls goroutine allocation
	results := make(chan *blockPayload, resultsBufferSize) // collects individual completed results
	var dcount uint64 = 0                                  // keep track of dispatched block processing jobs
	var rcount uint64 = 0                                  // count of results received
	c.FillInBuffer()
Loop:
	for {
		select {
		case sem <- 1:
			if i := c.i + dcount; dcount < modes.NBufferBlocks && i < c.NBlocks() {
				go func(b *blockPayload) {
					b.process()
					results <- b
					<-sem
				}(newBlockPayload(c.Cf(), i, c.GetBlock(i), getCounterBlock(c.nonce, i), c.Ck))
				dcount++
			}
		case b := <-results:
			c.PutBlock(b.i, b.out)
			rcount++
			if i := c.i + rcount; rcount == modes.NBufferBlocks || i == c.NBlocks() {
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
	i      uint64         // block number
	in     state.State    // input block
	out    state.State    // output of block
	ck     []byte         // cipher key
	cb     state.State    // counter block
}

// newBlockPayload creates a new instance of a block payload
func newBlockPayload(c *cipher.Cipher, i uint64, in state.State, cb state.State, ck []byte) *blockPayload {
	return &blockPayload{
		i:      i,
		cipher: c,
		in:     in,
		ck:     ck,
		cb:     cb,
	}
}

// processBlock processes an individual block payload
func (b *blockPayload) process() {
	b.out = b.cipher.Encrypt(b.cb, b.ck) // cipher text from encrypting cipher block
	b.out.Xor(b.in)
}

// Encrypt encrypts the input using CTR mode
func (c *Counter) Encrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, false)
	c.processCore()
}

// Decrypt decrypts the input using CTR mode
func (c *Counter) Decrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte) {
	c.initCounter(offset, size, in, out, ck, nonce, true)
	c.processCore()
}

// getCounterBlock gets the ith counter block, the first 8 bytes of the block are the nonce the last 8 bytes
// representing the count.
func getCounterBlock(nonce uint64, i uint64) state.State {
	return state.State{High: i, Low: nonce}
}
