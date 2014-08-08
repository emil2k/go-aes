package modes

import (
	"bytes"
	"encoding/hex"
	mbytes "github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/util/rand"
	"io"
	"testing"
)

func TestCalculateBlocks(t *testing.T) {
	test := func(size int64, isDecrypt bool, blocks int64) {
		if x := calculateBlocks(size, isDecrypt); x != blocks {
			t.Errorf("Calculate blocks failed for %d (decrypting? %s) should be %d was %d", size, isDecrypt, blocks, x)
		}
	}
	test(1, false, 1)
	test(17, false, 2)
	test(16, true, 1)
}

func TestNBuffers(t *testing.T) {
	test := func(blocks, buffers int64) {
		if x := calculateBuffers(blocks); x != buffers {
			t.Errorf("Calculate buffers failed for %d should be %d was %d", blocks, buffers, x)
		}
	}
	test(1, 1)
	test(int64(NBufferBlocks), 1)
	test(int64(NBufferBlocks+1), 2)
}

// TestPadBlock test padding a block.
func TestPadBlock(t *testing.T) {
	block := rand.GetRand(BlockSize / 2)
	out := make([]byte, BlockSize/2)
	copy(out, block)
	for i := 0; i < BlockSize/2; i++ {
		out = append(out, byte(BlockSize/2))
	}
	if b := padBlock(block); !bytes.Equal(b, out) {
		t.Errorf("Block padding failed with %s", hex.EncodeToString(b))
	}
}

// TestUnpadBlock tests unpadding a block.
func TestUnpadBlock(t *testing.T) {
	out := rand.GetRand(BlockSize / 2) // expected output
	block := make([]byte, BlockSize/2)
	copy(block, out)
	block = padBlock(block)
	if b := unpadBlock(block); !bytes.Equal(b, out) {
		t.Errorf("Block unpadding failed with %s", hex.EncodeToString(b))
	}
}

// testGetBlock configures and tests the getting of a block.
// A nil indicates test for out of range panic.
func testGetBlock(t *testing.T, i int64, in []byte, block []byte, isDecrypt bool) {
	if block == nil {
		defer func() {
			if r := recover(); r != "Getting block that is out of range" {
				t.Errorf("Getting out of range block panic failed, %s", r)
			}
		}()
	}
	m := NewMode(nil)
	m.InitMode(0, int64(len(in)),
		bytes.NewReader(in),
		mbytes.NewReadWriteSeeker(make([]byte, len(in))),
		nil, isDecrypt)
	if b := m.GetBlock(i); !bytes.Equal(b, block) {
		t.Errorf("Get block failed with %s", hex.EncodeToString(b))
	}
}

func TestGetMiddleBlock(t *testing.T) {
	in := make([]byte, BlockSize)
	block := rand.GetRand(BlockSize)
	in = append(in, block...)
	for i := 0; i < BlockSize; i++ {
		in = append(in, 0x00)
	}
	testGetBlock(t, 1, in, block, false)
}

func TestGetEndBlock(t *testing.T) {
	in := make([]byte, 0)
	block := rand.GetRand(BlockSize / 2)
	in = append(in, block...)
	block = padBlock(block)
	testGetBlock(t, 0, in, block, false)
}

func TestGetEndCompleteBlock(t *testing.T) {
	in := rand.GetRand(BlockSize)
	block := make([]byte, 0)
	for i := 0; i < BlockSize; i++ {
		block = append(block, byte(BlockSize))
	}
	testGetBlock(t, 1, in, block, false)
}

func TestGetOutOfRangeBlock(t *testing.T) {
	in := rand.GetRand(BlockSize)
	testGetBlock(t, 2, in, nil, false)
}

func TestGetEndCompleteBlockDecrypt(t *testing.T) {
	in := rand.GetRand(BlockSize)
	block := make([]byte, len(in))
	copy(block, in)
	testGetBlock(t, 0, in, block, true)
}

func TestGetOutOfRangeBlockDecrypt(t *testing.T) {
	in := rand.GetRand(BlockSize)
	testGetBlock(t, 1, in, nil, true)
}

func testPutBlock(t *testing.T, i int64, inputSize int64, out []byte, block []byte, expected []byte, isDecrypt bool) {
	if block == nil {
		defer func() {
			if r := recover(); r != "Putting block that is out of range" {
				t.Errorf("Putting out of range block panic failed, %s", r)
			}
		}()
	}
	r := mbytes.NewReadWriteSeeker(make([]byte, 0)) // dummy reader, not used
	w := mbytes.NewReadWriteSeeker(out)
	m := NewMode(nil)
	m.InitMode(0, inputSize, r, w, nil, isDecrypt)
	m.PutBlock(i, block)
	// Now retrieve put block to check
	b := make([]byte, BlockSize)
	_, _ = m.OutBuffer.Seek(i*int64(BlockSize), 0)
	n, err := m.OutBuffer.Read(b)
	if err != io.EOF && err != nil {
		t.Errorf("Unexpected error while trying to read put block : %s", err.Error())
	}
	b = b[:n] // trim the block
	if !bytes.Equal(b, expected) {
		t.Errorf("Put block failed with %s expected %s", hex.EncodeToString(b), hex.EncodeToString(expected))
	}
}

func TestPutMiddleBlock(t *testing.T) {
	out := make([]byte, 3*BlockSize)
	block := rand.GetRand(BlockSize)
	outBlock := make([]byte, len(block))
	copy(outBlock, block)
	testPutBlock(t, 1, int64(2*BlockSize), out, block, outBlock, false)
}

// TestPutEndBlockDecrypt tests the putting of the end block during the decryption of
// a 3 block input that contains a half a block of padding. When putting the last block
// to the output the half a block of padding should be removed.
func TestPutEndBlockDecrypt(t *testing.T) {
	out := make([]byte, 2*BlockSize+BlockSize/2)
	outBlock := rand.GetRand(BlockSize / 2) // the last block without padding
	block := make([]byte, len(outBlock))
	copy(block, outBlock)
	block = padBlock(block) // the last block with padding
	testPutBlock(t, 2, int64(3*BlockSize), out, block, outBlock, true)
}

// TestPutEndPaddingBlockDecrypt test the putting of an end block that is all padding
// during the decryption of a 2 block input. When putting the last block to the output
// the block should be discarded since it is all padding.
func TestPutEndPaddingBlockDecrypt(t *testing.T) {
	out := make([]byte, BlockSize)
	outBlock := make([]byte, 0)        // the last block without padding
	block := padBlock(make([]byte, 0)) // the last block with padding
	testPutBlock(t, 1, int64(2*BlockSize), out, block, outBlock, true)
}
