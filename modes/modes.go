package modes

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/state"
	mlog "github.com/emil2k/go-aes/util/log"
	"io"
	"io/ioutil"
	"log"
)

const BlockSize uint64 = 16             // size of processing blocks in bytes
const NBufferBlocks uint64 = 100 * 1000 // number of blocks to store in the buffer

// ModeInterface defines the common methods that need to be implemented to operate
// as a block cipher mode.
type ModeInterface interface {
	Encrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	Decrypt(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, nonce []byte)
	mlog.LeveledLogger
}

// Mode contains common components for representing the state of block cipher modes
type Mode struct {
	Cf        cipher.CipherFactory // creates an instance of the block cipher
	Ck        []byte               // cipher key
	offset    uint64               // offset in bytes, on input if decrypting on output if encrypting
	In        io.ReadSeeker        // input data stream
	InBuffer  []state.State        // input buffer
	size      uint64               // size of original input in bytes
	blocks    uint64               // number of blocks to process
	buffers   uint64               // number of buffer blocks to process
	Out       io.WriteSeeker       // ouput data stream
	OutBuffer []state.State        // output buffer
	putMax    uint64               // tracks maximum put index for trimming output buffer
	flushed   uint64               // number of flushed output buffers
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
// Requires size and offset of input in bytes as uint64.
func (m *Mode) InitMode(offset uint64, size uint64, in io.ReadSeeker, out io.WriteSeeker, ck []byte, isDecrypt bool) {
	m.IsDecrypt = isDecrypt
	m.In = in
	m.Out = out
	m.Ck = ck
	m.offset = offset
	// Seek the offset in the input file if decrypting or the output file if encrypting.
	if m.IsDecrypt {
		if _, seekErr := m.In.Seek(int64(m.offset), 0); seekErr != nil {
			m.ErrorLog.Panicln("Init mode seek input error : ", seekErr.Error())
		}
	} else {
		if _, seekErr := m.Out.Seek(int64(m.offset), 0); seekErr != nil {
			m.ErrorLog.Panicln("Init mode seek output error : ", seekErr.Error())
		}
	}
	m.size = size
	m.blocks = calculateBlocks(size, isDecrypt)
	m.buffers = calculateBuffers(m.blocks)
	m.InBuffer = make([]state.State, 0, calculateBufferSize(m.blocks)) // grows to capacity
	m.OutBuffer = make([]state.State, calculateBufferSize(m.blocks))   // filled asynchronously
	m.flushed = 0
	m.putMax = 0
}

// GetBlock gets the ith input block, a State instance, from the input buffer.
func (m *Mode) GetBlock(i uint64) state.State {
	bi := i % NBufferBlocks // in the current buffer block
	return m.InBuffer[bi]
}

// FillInBuffer reads in bytes from the main input converts them into State instances and stores
// them in the input buffer, reset the buffer before starting. Buffering is meant reduce the number
// of times the procesee seeks and reads from disk.
func (m *Mode) FillInBuffer() {
	m.InBuffer = m.InBuffer[0:0]           // resets the input buffer
	for i := 0; i < cap(m.InBuffer); i++ { // read in bytes for each state
		t := make([]byte, BlockSize)
		if n, err := m.In.Read(t); err != nil && err != io.EOF {
			m.ErrorLog.Println("Filling in buffer error when reading from input : ", err.Error())
		} else if uint64(n) < BlockSize {
			if !m.IsDecrypt {
				t = t[:n] // trim block
				t = padBlock(t)
				m.InBuffer = append(m.InBuffer, *state.NewStateFromBytes(t))
			}
			break // no more to read for this buffer
		} else {
			m.InBuffer = append(m.InBuffer, *state.NewStateFromBytes(t))
		}
	}
}

// padBlock pads an incomplete block with bytes to reach the block size.
// The padding bytes hold the number of padded bytes.
func padBlock(b []byte) []byte {
	pad := BlockSize - uint64(len(b))
	for i := uint64(0); i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

// calculateBufferSize determines the size of the input buffer in number of block based on the block
// to process. This is done to optimize the input buffer size adjusting it for smaller inputs.
func calculateBufferSize(blocks uint64) uint64 {
	if nbb := NBufferBlocks; blocks < nbb {
		return blocks
	} else {
		return nbb
	}
}

// FlusOutBuffer flushes the output buffer to the out writer, then truncates the buffer.
// Buffering and flushing is meant to reduce the number of times need to write to disk.
func (m *Mode) FlushOutBuffer() {
	for _, s := range m.OutBuffer[:m.putMax%NBufferBlocks+1] { // trim based on maximum put index
		m.flushed++
		b := s.GetBytes()
		if m.IsDecrypt && m.flushed == m.blocks { // last block to flush
			b = unpadBlock(b)
		}
		if _, err := m.Out.Write(b); err != nil {
			m.ErrorLog.Println("Flushing output buffer write error : ", err.Error())
		}
	}
	m.OutBuffer = make([]state.State, calculateBufferSize(m.blocks)) // resets the buffer
}

// PutBlock sets the ith output block, removing padding of the last block.
// If the last block is all padding won't write anything.
func (m *Mode) PutBlock(i uint64, b state.State) {
	bi := i % NBufferBlocks // in the current buffer
	m.OutBuffer[bi] = b
	if i > m.putMax {
		m.putMax = i
	}
}

// unpadBlock removes the padding of the last block.
func unpadBlock(b []byte) []byte {
	pad := int(b[len(b)-1])
	return b[:len(b)-pad]
}

// calculateBlocks calculates the number of blocks that need to be processed, based on input size.
func calculateBlocks(size uint64, isDecrypt bool) (blocks uint64) {
	blocks = size / BlockSize
	if !isDecrypt {
		blocks++
	}
	return
}

// NBlocks returns the number of blocks that will need to be processed.
func (m *Mode) NBlocks() uint64 {
	return m.blocks
}

// calculateBuffers calculates the number of buffers blocks that need to be processed, based on the
// the number of blocks to process.
func calculateBuffers(blocks uint64) (buffers uint64) {
	buffers = blocks / NBufferBlocks
	if blocks%NBufferBlocks != 0 {
		buffers++
	}
	return
}

// NBuffers returns the number of buffers that will need to be processed.
func (m *Mode) NBuffers() uint64 {
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
