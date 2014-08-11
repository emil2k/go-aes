package modes

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/util/bytes"
	mlog "github.com/emil2k/go-aes/util/log"
	"io"
	"io/ioutil"
	"log"
)

const BlockSize int = 16             // size of processing blocks in bytes
const NBufferBlocks int = 100 * 1000 // number of blocks to store in the buffer

// ModeInterface defines the common methods that need to be implemented to operate
// as a block cipher mode.
type ModeInterface interface {
	Encrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	Decrypt(offset int64, size int64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	mlog.LeveledLogger
}

// Mode contains common components for representing the state of block cipher modes
type Mode struct {
	Cf        cipher.CipherFactory   // creates an instance of the block cipher
	Ck        []byte                 // cipher key
	offset    int64                  // offset in bytes, on input if decrypting on output if encrypting
	In        io.ReadSeeker          // input data stream
	InBuffer  *bytes.ReadWriteSeeker // input buffer
	size      int64                  // size of original input in bytes
	blocks    int64                  // number of blocks to process
	buffers   int64                  // number of buffer blocks to process
	flushed   bool                   // whether end of file was reached on input data stream
	padded    bool                   // whether input stream has already been padded, only for encryption
	Out       io.WriteSeeker         // ouput data stream
	OutBuffer *bytes.ReadWriteSeeker // output buffer
	IsDecrypt bool                   // whether running decryption
	ErrorLog  *log.Logger            // log for errors
	InfoLog   *log.Logger            // log for non-verbose output
	DebugLog  *log.Logger            // log for verbose output
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
	m.InBuffer = bytes.NewReadWriteSeeker(make([]byte, 0, NBufferBlocks*BlockSize))
	m.Out = out
	m.OutBuffer = bytes.NewReadWriteSeeker(make([]byte, 0, NBufferBlocks*BlockSize))
	m.Ck = ck
	m.offset = offset
	// Seek the offset in the input file if decrypting or the output file if encrypting.
	if m.IsDecrypt {
		if _, seekErr := m.In.Seek(m.offset, 0); seekErr != nil {
			m.ErrorLog.Panicln("Init mode seek input error : ", seekErr.Error())
		}
	} else {
		if _, seekErr := m.Out.Seek(m.offset, 0); seekErr != nil {
			m.ErrorLog.Panicln("Init mode seek output error : ", seekErr.Error())
		}
	}
	m.size = size
	m.blocks = calculateBlocks(size, isDecrypt)
	m.buffers = calculateBuffers(m.blocks)
}

// GetBlock gets the ith input block copies data into a slice
// with a new underlying array. Keeps track of input size.
func (m *Mode) GetBlock(i int64) []byte {
	if i+1 > m.blocks {
		m.ErrorLog.Panicf("Getting block that is out of range")
	}
	seek := i % int64(NBufferBlocks) * int64(BlockSize) // seek in the current buffer block
	if _, seekErr := m.InBuffer.Seek(seek, 0); seekErr != nil {
		m.ErrorLog.Panicln("Get block seek error :", seekErr.Error())
	}
	t := make([]byte, BlockSize)
	if n, err := m.InBuffer.Read(t); err != nil && err != io.EOF {
		m.ErrorLog.Panicln("Get block read error :", err.Error())
	} else if n < BlockSize {
		m.flushed = true
		if !m.padded {
			t = padBlock(t[:n]) // trim to only read bytes
			m.padded = true
		}
	}
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

// FillInBuffer reads in bytes into the input buffer. Buffering is meant reduce the
// number of times seeking and reading from disk.
func (m *Mode) FillInBuffer() {
	t := make([]byte, calculateInputBufferSize(m.size))
	if _, err := m.In.Read(t); err != nil {
		m.ErrorLog.Println("Filling in buffer error when reading from input : ", err.Error())
	}
	if _, err := m.InBuffer.Write(t); err != nil {
		m.ErrorLog.Println("Filling in buffer error : ", err.Error())
	}
}

// calculateInputBufferSize determines the size of the input buffer based on the original input size.
func calculateInputBufferSize(inputSize int64) int64 {
	bpb := int64(NBufferBlocks * BlockSize) // bytes per buffer block
	if r := inputSize % bpb; r == 0 {
		return bpb
	} else {
		return r
	}
}

// TruncateInBuffer resets the input buffer.
func (m *Mode) TruncateInBuffer() {
	m.InBuffer.Truncate()
}

// FlusOutBuffer flushes the output buffer to the out writer, truncating the buffer.
// Buffering and flushing is meant to reduce the number of times need to write to disk.
func (m *Mode) FlushOutBuffer() {
	if _, err := m.Out.Write(m.OutBuffer.Bytes()); err != nil {
		m.ErrorLog.Println("Flushing output buffer error : ", err.Error())
	}
	m.OutBuffer.Truncate() // resets the buffer
}

// PutBlock sets the ith output block, removing padding of the last block.
// If the last block is all padding won't write anything.
func (m *Mode) PutBlock(i int64, b []byte) {
	if i+1 > m.blocks {
		m.ErrorLog.Panicf("Putting block that is out of range")
	}
	seek := i % int64(NBufferBlocks) * int64(BlockSize) // seek in the current buffer
	if _, seekErr := m.OutBuffer.Seek(seek, 0); seekErr != nil {
		m.ErrorLog.Panicln("Put block in output buffer seek error :", seekErr.Error())
	}
	if m.IsDecrypt && int64(i+1) == m.blocks { // during decryption remove padding from last block
		b = unpadBlock(b)
	}
	if len(b) > 0 {
		if _, err := m.OutBuffer.Write(b); err != nil {
			m.ErrorLog.Panicln("Put block in output buffer write error :", err.Error())
		}
	}
}

// unpadBlock removes the padding of the last block.
func unpadBlock(b []byte) []byte {
	pad := int(b[len(b)-1])
	return b[:len(b)-pad]
}

// calculateBlocks calculates the number of blocks that need to be processed, based on input size.
func calculateBlocks(size int64, isDecrypt bool) (blocks int64) {
	blocks = size / int64(BlockSize)
	if !isDecrypt {
		blocks++
	}
	return
}

// NBlocks returns the number of blocks that will need to be processed.
func (m *Mode) NBlocks() int64 {
	return m.blocks
}

// calculateBuffers calculates the number of buffers blocks that need to be processed, based on the
// the number of blocks to process.
func calculateBuffers(blocks int64) (buffers int64) {
	buffers = blocks / int64(NBufferBlocks)
	if blocks%int64(NBufferBlocks) != 0 {
		buffers++
	}
	return
}

// NBuffers returns the number of buffers that will need to be processed.
func (m *Mode) NBuffers() int64 {
	return m.buffers
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
