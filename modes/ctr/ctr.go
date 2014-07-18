package ctr

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
)
import "github.com/emil2k/go-aes/cipher"

// Counter keeps track of the state of a counter cipher mode
// used for encryption or decryption
type Counter struct {
	cf        cipher.CipherFactory // block cipher factory to use
	i         int                  // keeps track of the counter
	isDecrypt bool                 // whether decryption, otherwise encryption
	nonce     []byte               // initialization vector
	ck        []byte               // cipher key
	in        []byte               // input plain or cipher text
	out       []byte               // output cipher or plain text
	ErrorLog  *log.Logger          // log for errors
	InfoLog   *log.Logger          // log for non-verbose output
	DebugLog  *log.Logger          // log for verbose output
}

// NewCounter creates a new counter with the given Cipher instance
func NewCounter(cf cipher.CipherFactory) *Counter {
	return &Counter{
		cf:       cf,
		ErrorLog: log.New(ioutil.Discard, "", 0),
		InfoLog:  log.New(ioutil.Discard, "", 0),
		DebugLog: log.New(ioutil.Discard, "", 0),
	}
}

// initCounter initializes a counter either for encryption or decryption
func (c *Counter) initCounter(in []byte, ck []byte, nonce []byte, isDecrypt bool) {
	c.i = 0
	c.isDecrypt = isDecrypt
	c.ck = ck
	c.nonce = nonce
	c.in = in
	c.out = make([]byte, c.outputLength())
}

// outputLength determines the size of the output slice to allocate
// depends on input length and whether decrypting or encrypting
func (c *Counter) outputLength() (outLen int) {
	inLen := len(c.in)
	if c.isDecrypt {
		outLen = inLen
		c.DebugLog.Println("decryption output length", outLen, "based on input length", inLen)
	} else {
		outLen = inLen + 16 - (inLen % 16)
		c.DebugLog.Println("encryption output length", outLen, "based on input length", inLen)
	}
	return
}

// processCounterCore runs the core of the counter mode each block is run
// on separate goroutines and gathered together at the end
func (c *Counter) processCounterCore() {
	c.DebugLog.Println(runtime.NumCPU(), "number of CPUs")
	blocks := len(c.in) / 16
	sem := make(chan int, runtime.NumCPU())     // controls goroutine allocation
	results := make(chan *blockPayload, blocks) // collects individual completed results
	for c.i < blocks {
		sem <- 1
		go func(b *blockPayload) {
			c.DebugLog.Println("running block", b.i)
			processBlock(b)
			results <- b
			<-sem
		}(c.newBlockPayload(c.i, c.ck))
		c.i++
	}
	// Put results together
	for i := 0; i < blocks; i++ {
		b := <-results
		min, max := b.i*16, (b.i+1)*16
		c.DebugLog.Println("gathering result from block", b.i)
		c.DebugLog.Printf("copying into range [%d, %d) of output length %d\n", min, max, len(c.out))
		copy(c.out[b.i*16:(b.i+1)*16], b.out)
	}
}

// blockPayload keeps the state of a block while it is being processed
// in a goroutine and is then sent back as the result over a channel
type blockPayload struct {
	cipher *cipher.Cipher // block cipher used
	i      int            // block count
	in     []byte         // input block
	out    []byte         // output of block
	ck     []byte         // cipher key
	cb     []byte         // counter block
}

// newBlockPayload creates a new instance of a block payload
func (c *Counter) newBlockPayload(i int, ck []byte) *blockPayload {
	return &blockPayload{
		i:      i,
		cipher: c.cf(),
		in:     c.getBlock(i),
		out:    make([]byte, 0),
		ck:     ck,
		cb:     c.getCounterBlock(i),
	}
}

// processBlock processes an individual block payload
func processBlock(b *blockPayload) {
	b.cipher.DebugLog.Println("process block", b.i)
	cc := b.cipher.Encrypt(b.cb, b.ck) // cipher text from encrypting cipher block
	b.out = make([]byte, len(b.in))
	for i, v := range b.in {
		b.out[i] = v ^ cc[i]
	}
}

// Encrypt encrypts the input using CTR mode
func (c *Counter) Encrypt(in []byte, ck []byte, nonce []byte) []byte {
	c.initCounter(in, ck, nonce, false)
	c.addPadding()
	c.processCounterCore()
	return c.out
}

// Decrypt decrypts the input using CTR mode
func (c *Counter) Decrypt(in []byte, ck []byte, nonce []byte) []byte {
	c.initCounter(in, ck, nonce, true)
	c.processCounterCore()
	c.removePadding()
	return c.out
}

// addPadding pads the input to get a positive number of 16 byte blocks
// padded with n bytes of n value bytes, if already divides into 16 byte block
// attach a full 16 byte block with 16 stored in each byte
func (c *Counter) addPadding() {
	pad := 16 - (len(c.in) % 16)
	for i := 0; i < pad; i++ {
		c.in = append(c.in, byte(pad))
	}
}

// removePadding removes the padding of a decrypted plaintext output
func (c *Counter) removePadding() {
	pad := int(c.out[len(c.out)-1])
	c.out = c.out[:len(c.out)-pad]
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

// getBlock gets the ith input block copies data into a slice
// with a new underlying array
func (c *Counter) getBlock(i int) []byte {
	t := make([]byte, 16)
	copy(t, c.in[i*16:(i+1)*16])
	return t
}

// NewNonce generates a new 8 byte nonce, returns nonce slice and error
func NewNonce() ([]byte, error) {
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	return nonce, err
}
