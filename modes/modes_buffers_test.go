package modes

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/state"
	mbytes "github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/util/rand"
	"testing"
)

// TestFillInBuffer test a regular block without padding input into the buffer.
func TestFillInBuffer(t *testing.T) {
	bc := 3 // buffer state capacity
	data := rand.GetRand(bc * int(BlockSize))
	m := &Mode{
		In:        mbytes.NewReadWriteSeeker(data),
		InBuffer:  make([]state.State, 0, bc),
		IsDecrypt: true, // no padding during decryption
	}
	m.FillInBuffer()
	for i := uint64(0); i < uint64(bc); i++ { // iterate through and compare buffer to data
		expected := *state.NewStateFromBytes(data[i*BlockSize : (i+1)*BlockSize])
		if x := m.InBuffer[i]; x != expected {
			t.Errorf("Fill input buffer failed on the %d state with %s, expected %s", i, x, expected)
		}
	}
}

// TestFillInBufferPartialPadding test padding of partial block when reading input during encryption.
func TestFillInBufferPartialPadding(t *testing.T) {
	bc := 1 // buffer state capacity
	data := rand.GetRand(int(BlockSize) / 2)
	m := &Mode{
		In:        mbytes.NewReadWriteSeeker(data),
		InBuffer:  make([]state.State, 0, bc),
		IsDecrypt: false, // padding during encryption
	}
	m.FillInBuffer()
	expected := *state.NewStateFromBytes(padBlock(data))
	if x := m.InBuffer[0]; x != expected {
		t.Errorf("Fill in buffer during encryption with partial padding failed with %s, expected %s", x, expected)
	}
}

// TestFillInBufferWholePadding test padding of whole block, meaning input is divisble by the block size, when
// reading input during encryption.
func TestFillInBufferWholePadding(t *testing.T) {
	bc := 2 // buffer state capacity
	data := rand.GetRand(int(BlockSize))
	m := &Mode{
		In:        mbytes.NewReadWriteSeeker(data),
		InBuffer:  make([]state.State, 0, bc),
		IsDecrypt: false, // padding during encryption
	}
	m.FillInBuffer()
	expected := *state.NewStateFromBytes(padBlock(make([]byte, 0)))
	if x := m.InBuffer[1]; x != expected { // get the padded block
		t.Errorf("Fill in buffer during encryption with whole padding failed with %s, expected %s", x, expected)
	}
}

// TestFillInBufferNoPadding test that there is no padding when filling input buffer during decryption.
func TestFillInBufferNoPadding(t *testing.T) {
	bc := 3 // buffer state capacity
	data := rand.GetRand(int(BlockSize))
	m := &Mode{
		In:        mbytes.NewReadWriteSeeker(data),
		InBuffer:  make([]state.State, 0, bc),
		IsDecrypt: true, // no padding during decryption
	}
	m.FillInBuffer()
	if len(m.InBuffer) != 1 {
		t.Errorf("Fill in buffer without padding during decryption failed")
	}
}

// TestFillInBufferResetting test that the buffer is reset and truncated before being filled each time.
// Reads in 3 blocks, 2 blocks at time after second fill buffer should contain one block, checks that
// the block matches expectations.
func TestFillInBufferResetting(t *testing.T) {
	bc := 2 // buffer state capacity
	data := rand.GetRand(int(BlockSize) * 3)
	m := &Mode{
		In:        mbytes.NewReadWriteSeeker(data),
		InBuffer:  make([]state.State, 0, bc),
		IsDecrypt: true, // no padding during decryption
	}
	m.FillInBuffer()
	m.FillInBuffer()
	expected := *state.NewStateFromBytes(data[2*BlockSize : 3*BlockSize]) // should contain last block
	if len(m.InBuffer) != 1 {
		t.Errorf("Fill in buffer reseting failed because more than one block left")
	} else if x := m.InBuffer[0]; x != expected {
		t.Errorf("Fill in buffer reseting failed because with last block %s, expected %s", x, expected)
	}
}

// TestFlushOutBuffer tests regular flushing out of the output buffer witout unpadding during encryption.
// Tests that each block in the output matches expectations and that the output buffer is truncated.
func TestFlushOutBuffer(t *testing.T) {
	bc := 3 // buffer state capacity
	data := rand.GetRand(int(BlockSize) * bc)
	out := mbytes.NewReadWriteSeeker(make([]byte, 0, len(data)))
	m := &Mode{
		Out:       out,
		OutBuffer: make([]state.State, bc), // just as in init mode
		IsDecrypt: false,                   // no unpadding during encryption
		blocks:    calculateBlocks(uint64(len(data)), false),
		buffers:   1,
	}
	for i := uint64(0); i < uint64(bc); i++ { // fill in output buffer with blocks
		m.PutBlock(i, *state.NewStateFromBytes(data[i*BlockSize : (i+1)*BlockSize]))
	}
	m.FlushOutBuffer()
	for i := uint64(0); i < uint64(bc); i++ {
		expected := data[i*BlockSize : (i+1)*BlockSize]
		if x := (out.Bytes())[i*BlockSize : (i+1)*BlockSize]; !bytes.Equal(x, expected) {
			t.Errorf("Flushing output buffer failed on %d block with %s, expected %s", i, hex.EncodeToString(x), hex.EncodeToString(expected))
		}
	}
	if uint64(len(m.OutBuffer)) != calculateBufferSize(m.blocks) {
		t.Errorf("Flushing output buffer failed buffer not reset")
	}
}

// TestFlushOutBufferPartialUnpadding tests unpadding of a partial block when flushing the output buffer during decryption.
func TestFlushOutBufferPartialUnpadding(t *testing.T) {
	bc := 1 // buffer state capacity
	block := rand.GetRand(int(BlockSize) / 2)
	data := padBlock(block)
	out := mbytes.NewReadWriteSeeker(make([]byte, 0, len(data)))
	m := &Mode{
		Out:       out,
		OutBuffer: make([]state.State, bc), // just as in init mode
		IsDecrypt: true,                    // unpadding during decryption
		blocks:    calculateBlocks(uint64(len(data)), true),
		buffers:   1,
	}
	m.OutBuffer[0] = *state.NewStateFromBytes(data) // fill in output buffer
	m.FlushOutBuffer()
	if x := out.Bytes(); !bytes.Equal(x, block) {
		t.Errorf("Flushing output buffer during decryption with partial unpadding failed with %s, expected %s", hex.EncodeToString(x), hex.EncodeToString(block))
	}
}

// TestFlushOutBufferWholeUnpadding tests unpadding of a whole block when flushing the output buffer during decryption.
func TestFlushOutBufferWholeUnpadding(t *testing.T) {
	bc := 1 // buffer state capacity
	block := make([]byte, 0)
	data := padBlock(block)
	out := mbytes.NewReadWriteSeeker(make([]byte, 0, len(data)))
	m := &Mode{
		Out:       out,
		OutBuffer: make([]state.State, bc), // just as in init mode
		IsDecrypt: true,                    // unpadding during decryption
		blocks:    calculateBlocks(uint64(len(data)), true),
		buffers:   1,
	}
	m.OutBuffer[0] = *state.NewStateFromBytes(data) // fill in output buffer
	m.FlushOutBuffer()
	if x := out.Bytes(); !bytes.Equal(x, block) {
		t.Errorf("Flushing output buffer during decryption with whole unpadding failed with %s, expected %s", hex.EncodeToString(x), hex.EncodeToString(block))
	}
}

// TestFlushOutBufferNoUnpadding tests that there is no unpadding when flushing output buffer during encryption.
func TestFlushOutBufferNoUnpadding(t *testing.T) {
	bc := 1 // buffer state capacity
	block := rand.GetRand(int(BlockSize))
	data := block
	out := mbytes.NewReadWriteSeeker(make([]byte, 0, len(data)))
	m := &Mode{
		Out:       out,
		OutBuffer: make([]state.State, bc), // just as in init mode
		IsDecrypt: false,                   // no unpadding during encryption
		blocks:    calculateBlocks(uint64(len(data)), false),
		buffers:   1,
	}
	m.OutBuffer[0] = *state.NewStateFromBytes(data) // fill in output buffer
	m.FlushOutBuffer()
	if x := out.Bytes(); !bytes.Equal(x, block) {
		t.Errorf("Flushing output buffer during encryption should have no unpadding failed with %s, expected %s", hex.EncodeToString(x), hex.EncodeToString(block))
	}
}

// TestFlushOutBufferUnderCapacity tests flushing out a buffer block that is filled under buffer capacity, which can happen
// when the last block contains less than NBufferBlocks.
func TestFlushOutBufferUnderCapacity(t *testing.T) {
	bc := NBufferBlocks // buffer state capacity
	block := rand.GetRand(int(BlockSize))
	data := rand.GetRand(int(NBufferBlocks * BlockSize)) // first buffer block is random data
	data = append(data, block...)                        // second block is filled under capacity with just one block
	out := mbytes.NewReadWriteSeeker(make([]byte, 0, len(data)))
	m := &Mode{
		Out:       out,
		OutBuffer: make([]state.State, bc), // just as in init mode
		IsDecrypt: false,                   // no unpadding during encryption
		blocks:    calculateBlocks(uint64(len(data)), true),
		buffers:   2,
	}
	for i := uint64(0); i < m.blocks; i++ { // fill in output buffer with blocks
		if i > 0 && i%uint64(bc) == 0 { // buffer capacity reached
			m.FlushOutBuffer()
		}
		m.PutBlock(i, *state.NewStateFromBytes(data[i*BlockSize : (i+1)*BlockSize]))
	}
	m.FlushOutBuffer() // the remainder
	if x := out.Bytes()[NBufferBlocks*BlockSize:]; len(x) != int(BlockSize) {
		t.Errorf("Flushing out buffer with output buffer filled under capacity failed, last buffer block should contain only one block not %d blocks", len(x)/int(BlockSize))
	} else if !bytes.Equal(x, block) { // compare the second buffer block
		t.Errorf("Flushing output buffer with output buffer filled under capacity failed with %s, expected %s", hex.EncodeToString(x), hex.EncodeToString(block))
	}
}

func TestCalculateBufferSize(t *testing.T) {
	test := func(blocks, expectedBufferSize uint64) {
		if x := calculateBufferSize(blocks); x != expectedBufferSize {
			t.Errorf("Calculating buffer size failed with %d for %d blocks expected %d", x, blocks, expectedBufferSize)
		}
	}
	bpb := NBufferBlocks // bytes per buffer block
	test(1, 1)
	test(bpb+1, bpb)
	test(bpb*3, bpb)
}

func TestCalculateBuffers(t *testing.T) {
	test := func(blocks, buffers uint64) {
		if x := calculateBuffers(blocks); x != buffers {
			t.Errorf("Calculate buffers failed for %d should be %d was %d", blocks, buffers, x)
		}
	}
	test(1, 1)
	test(NBufferBlocks, 1)
	test(NBufferBlocks+1, 2)
}

func TestNBuffers(t *testing.T) {
	m := &Mode{buffers: 15}
	if m.NBuffers() != 15 {
		t.Errorf("NBuffers failed")
	}
}
