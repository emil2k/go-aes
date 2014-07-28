package modes

import (
	"encoding/hex"
	"github.com/emil2k/go-aes/cipher"
	mlog "github.com/emil2k/go-aes/util/log"
	"io"
	"io/ioutil"
	"log"
)

const BlockSize int = 16 // size of processing blocks in bytes

// ModeInterface defines the common methods that need to be implemented to operate
// as a block cipher mode.
type ModeInterface interface {
	Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	mlog.LeveledLogger
}

// Mode contains common components for representing the state of block cipher modes
type Mode struct {
	Cf        cipher.CipherFactory // creates an instance of the block cipher
	Ck        []byte               // cipher key
	In        io.ReadSeeker        // input data stream
	offset    int64                // offset in bytes in the original input
	size      int64                // size of original input in bytes
	blocks    int64                // number of blocks to process
	flushed   bool                 // whether end of file was reached on input data stream
	padded    bool                 // whether input stream has already been padded, only for encryption
	Out       io.WriteSeeker       // ouput data stream
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

// InitMode initiates the mode for an encryption or decryption process.
// Requires size and offset of input in bytes as int64.
func (m *Mode) InitMode(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, isDecrypt bool) {
	m.IsDecrypt = isDecrypt
	m.In = in
	m.Out = out
	m.Ck = ck
	m.offset = offset
	m.size = size
	m.blocks = size / int64(BlockSize)
	if !isDecrypt {
		m.blocks++
	}
}

// GetBlock gets the ith input block copies data into a slice
// with a new underlying array. Keeps track of input size.
func (m *Mode) GetBlock(i int) []byte {
	if int64(i+1) > m.blocks {
		m.ErrorLog.Panicf("Getting block that is out of range")
	}
	seek := int64(i * BlockSize)
	if m.IsDecrypt {
		seek += m.offset // offset for metadata during decryption
	}
	m.DebugLog.Println("get block seek", seek)
	if _, seekErr := m.In.Seek(seek, 0); seekErr != nil {
		m.ErrorLog.Panicln("Get block seek error :", seekErr.Error())
	}
	t := make([]byte, BlockSize)
	if n, err := m.In.Read(t); err != nil && err != io.EOF {
		m.ErrorLog.Panicln("Get block read error :", err.Error())
	} else if n < BlockSize {
		m.flushed = true
		if !m.padded {
			t = padBlock(t[:n]) // trim to only read bytes
			m.padded = true
		}
	}
	m.DebugLog.Printf("get block %d", i)
	return t
}

// padBlock pads an incomplete block with bytes to reach the block size.
// The padding bytes hold the number of padded bytes.
func padBlock(b []byte) []byte {
	pad := BlockSize - len(b)
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

// PutBlock sets the ith output block, removing padding of the last block.
// If the last block is all padding won't write anything.
func (m *Mode) PutBlock(i int, b []byte) {
	if int64(i+1) > m.blocks {
		m.ErrorLog.Panicf("Putting block that is out of range")
	}
	seek := int64(i * BlockSize)
	if !m.IsDecrypt {
		seek += m.offset // offset for metadata during encryption
	}
	m.DebugLog.Println("putting block seek", seek)
	if _, seekErr := m.Out.Seek(seek, 0); seekErr != nil {
		m.ErrorLog.Panicln("Put block seek error :", seekErr.Error())
	}
	if m.IsDecrypt && int64(i+1) == m.blocks { // during decryption remove padding from last block
		b = unpadBlock(b)
	}
	if len(b) > 0 {
		if _, err := m.Out.Write(b); err != nil {
			m.ErrorLog.Panicln("Put block write error :", err.Error())
		}
		m.DebugLog.Printf("puting block %d %s", i, hex.EncodeToString(b))
	}
}

// unpadBlock removes the padding of the last block
func unpadBlock(b []byte) []byte {
	pad := int(b[len(b)-1])
	return b[:len(b)-pad]
}

// NBlocks returns the number of blocks that need to be processed
func (m *Mode) NBlocks() int64 {
	return m.blocks
}

// SetErrorLog sets the error log.
func (m *Mode) SetErrorLog(errorLog *log.Logger) {
	m.ErrorLog = errorLog
}

// SetInfoLog sets the error log.
func (m *Mode) SetInfoLog(infoLog *log.Logger) {
	m.InfoLog = infoLog
}

// SetDebugLog sets the error log.
func (m *Mode) SetDebugLog(debugLog *log.Logger) {
	m.DebugLog = debugLog
}
