package modes

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/state"
	"github.com/emil2k/go-aes/util/rand"
	"testing"
)

func TestGetBlock(t *testing.T) {
	block := *state.NewStateFromBytes(rand.GetRand(int(BlockSize)))
	m := &Mode{
		InBuffer: []state.State{block},
		blocks:   NBufferBlocks * 10,
	}
	if x := m.GetBlock(NBufferBlocks * 5); x != block { // gets the first 1st block in the 5th buffer block
		t.Errorf("Get block failed with %s, expected %s", x, block)
	}
}

func TestPutBlock(t *testing.T) {
	block := *state.NewStateFromBytes(rand.GetRand(int(BlockSize)))
	blocks := NBufferBlocks * 10
	m := &Mode{
		OutBuffer: make([]state.State, calculateBufferSize(blocks)), // same as in init mode
		blocks:    blocks,
	}
	i := NBufferBlocks * 5 // puts the first 1st block in the 5th buffer block
	m.PutBlock(i, block)
	if x := m.OutBuffer[0]; x != block {
		t.Errorf("Put block failed with %s, expected %s", x, block)
	}
}

func TestCalculateBlocks(t *testing.T) {
	test := func(size uint64, isDecrypt bool, blocks uint64) {
		if x := calculateBlocks(size, isDecrypt); x != blocks {
			t.Errorf("Calculate blocks failed for %d (decrypting? %s) should be %d was %d", size, isDecrypt, blocks, x)
		}
	}
	test(1, false, 1)
	test(17, false, 2)
	test(16, true, 1)
}

func TestNBlocks(t *testing.T) {
	m := &Mode{blocks: 15}
	if m.NBlocks() != 15 {
		t.Errorf("NBlocks failed")
	}
}

func TestPadBlock(t *testing.T) {
	block := rand.GetRand(int(BlockSize) / 2)
	out := make([]byte, BlockSize/2)
	copy(out, block)
	for i := uint64(0); i < BlockSize/2; i++ {
		out = append(out, byte(BlockSize/2))
	}
	if b := padBlock(block); !bytes.Equal(b, out) {
		t.Errorf("Block padding failed with %s", hex.EncodeToString(b))
	}
}

func TestUnpadBlock(t *testing.T) {
	out := rand.GetRand(int(BlockSize / 2)) // expected output
	block := make([]byte, BlockSize/2)
	copy(block, out)
	block = padBlock(block)
	if b := unpadBlock(block); !bytes.Equal(b, out) {
		t.Errorf("Block unpadding failed with %s", hex.EncodeToString(b))
	}
}
