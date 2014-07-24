package modes

import (
	"crypto/rand"
	"github.com/emil2k/go-aes/cipher"
	"io/ioutil"
	"log"
)

// Mode contains common components for representing the state of block cipher modes
type Mode struct {
	Cf        cipher.CipherFactory // creates an instance of the block cipher
	Ck        []byte               // cipher key
	In        []byte               // input data
	Out       []byte               // ouput data
	IsDecrypt bool                 // whether running decryption
	ErrorLog  *log.Logger          // log for errors
	InfoLog   *log.Logger          // log for non-verbose output
	DebugLog  *log.Logger          // log for verbose output
}

// NewMode creates a new instance of a block cipher mode
func NewMode(cf cipher.CipherFactory) *Mode {
	return &Mode{
		Cf:       cf,
		ErrorLog: log.New(ioutil.Discard, "", 0),
		InfoLog:  log.New(ioutil.Discard, "", 0),
		DebugLog: log.New(ioutil.Discard, "", 0),
	}
}

// initMode initiates the mode for an encryption or decryption process
func (m *Mode) InitMode(in []byte, ck []byte, isDecrypt bool) {
	m.IsDecrypt = isDecrypt
	m.In = in
	m.Ck = ck
	m.Out = make([]byte, m.outputLength())
}

// outputLength determines the size of the output slice to allocate
// depends on input length and whether decrypting or encrypting
func (m *Mode) outputLength() (outLen int) {
	inLen := len(m.In)
	if inLen == 0 {
		m.DebugLog.Panicln("input not initiated")
	}
	if m.IsDecrypt {
		outLen = inLen
		m.DebugLog.Println("decryption output length", outLen, "based on input length", inLen)
	} else {
		outLen = inLen + 16 - (inLen % 16)
		m.DebugLog.Println("encryption output length", outLen, "based on input length", inLen)
	}
	return
}

// AddPadding pads the input to get a positive number of 16 byte blocks
// padded with n bytes of n value bytes, if already divides into 16 byte block
// attach a full 16 byte block with 16 stored in each byte
func (m *Mode) AddPadding() {
	pad := 16 - (len(m.In) % 16)
	for i := 0; i < pad; i++ {
		m.In = append(m.In, byte(pad))
	}
	m.DebugLog.Printf("added %d bytes of padding %d bytes of data", pad, len(m.In))
}

// RemovePadding removes the padding of a decrypted plaintext output
func (m *Mode) RemovePadding() {
	pad := int(m.Out[len(m.Out)-1])
	m.Out = m.Out[:len(m.Out)-pad]
	m.DebugLog.Printf("removed %d bytes of padding for %d bytes of ouput", pad, len(m.Out))
}

// GetBlock gets the ith input block copies data into a slice
// with a new underlying array
func (m *Mode) GetBlock(i int) []byte {
	t := make([]byte, 16)
	copy(t, m.In[i*16:(i+1)*16])
	return t
}

// PutBlock sets the ith output block
func (m *Mode) PutBlock(i int, value []byte) {
	min, max := i*16, (i+1)*16
	m.DebugLog.Printf("puting block %d, into range [%d, %d) of output length %d\n", i, min, max, len(m.Out))
	copy(m.Out[i*16:(i+1)*16], value)
}

// NBlocks returns the number of blocks that need to be processed
func (m *Mode) NBlocks() int {
	return len(m.Out) / 16
}

// NewNonce generates a new `n` byte nonce, returns nonce slice and error
func NewNonce(n int) ([]byte, error) {
	nonce := make([]byte, n)
	_, err := rand.Read(nonce)
	return nonce, err
}
