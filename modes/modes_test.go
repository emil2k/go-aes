package modes

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/util/rand"
	"log"
	"os"
	"testing"
)

func TestNewMode(t *testing.T) {
	m := NewMode(func() *cipher.Cipher { return cipher.NewCipher(cipher.CK128) })
	switch {
	case m.Cf == nil:
		t.Errorf("New mode failed cipher factory not set")
	case m.ErrorLog == nil, m.InfoLog == nil, m.DebugLog == nil:
		t.Errorf("New mode failed logs not set")
	}
}

func TestInitMode(t *testing.T) {
	m := NewMode(func() *cipher.Cipher { return cipher.NewCipher(cipher.CK128) })
	data := rand.GetRand(int(BlockSize) * 10)
	var offset, size uint64 = 10, uint64(len(data))
	in := bytes.NewReadWriteSeeker(data)
	out := bytes.NewReadWriteSeeker(make([]byte, len(data)))
	ck := rand.GetRand(16)
	isDecrypt := true
	blocks := calculateBlocks(size, isDecrypt)
	buffers := calculateBuffers(blocks)
	bufferSize := calculateBufferSize(blocks)
	m.InitMode(offset, size, in, out, ck, true)
	switch {
	case m.In == nil:
		t.Errorf("Init mode failed input not set")
	case m.Out == nil:
		t.Errorf("Init mode failed output not set")
	case m.Ck == nil:
		t.Errorf("Init mode failed cipher key not set")
	case m.IsDecrypt != isDecrypt:
		t.Errorf("Init mode failed is decrypt not set")
	case m.offset != offset:
		t.Errorf("Init mode failed offset not set")
	case m.size != size:
		t.Errorf("Init mode failed input size not set")
	case m.blocks != blocks:
		t.Errorf("Init mode failed blocks not set correctly")
	case m.buffers != buffers:
		t.Errorf("Init mode failed buffers not set correctly")
	case len(m.InBuffer) != 0 || uint64(cap(m.InBuffer)) != bufferSize:
		t.Errorf("Init mode failed input buffer not setup correctly")
	case uint64(len(m.OutBuffer)) != bufferSize:
		t.Errorf("Init mode failed output buffer not setup correctly")
	}
}

// TestInitModeDecryptOffsetSeek tests the offset seek during initialization on the input during decryption.
func TestInitModeDecryptOffsetSeek(t *testing.T) {
	in := bytes.NewReadWriteSeeker(make([]byte, 100))
	out := bytes.NewReadWriteSeeker(make([]byte, 100))
	m := Mode{}
	m.InitMode(10, 100, in, out, nil, true)
	if in.Position() != 10 {
		t.Errorf("Decrypt offset seek failed")
	} else if out.Position() != 0 {
		t.Errorf("Decrypt offset seek failed output position should not be offset")
	}
}

// TestInitModeEncryptOffsetSeek tests the offset seek during initialization on the output during encryption.
func TestInitModeEncryptOffsetSeek(t *testing.T) {
	in := bytes.NewReadWriteSeeker(make([]byte, 100))
	out := bytes.NewReadWriteSeeker(make([]byte, 100))
	m := Mode{}
	m.InitMode(10, 100, in, out, nil, false)
	if out.Position() != 10 {
		t.Errorf("Encrypt offset seek failed")
	} else if in.Position() != 0 {
		t.Errorf("Encrypt offset seek failed input position should not be offset")
	}
}

func TestInitModeReset(t *testing.T) {
	m := Mode{flushed: 5, putMax: 5}
	in := bytes.NewReadWriteSeeker(make([]byte, 100))
	out := bytes.NewReadWriteSeeker(make([]byte, 100))
	m.InitMode(10, 100, in, out, nil, false)
	switch {
	case m.putMax != 0:
		t.Errorf("Init mode failed put max not reset")
	case m.flushed != 0:
		t.Errorf("Init mode failed flushed not reset")
	}
}
func TestSetLogs(t *testing.T) {
	m := Mode{}
	m.SetErrorLog(log.New(os.Stdout, "test", 0))
	m.SetInfoLog(log.New(os.Stdout, "test", 0))
	m.SetDebugLog(log.New(os.Stdout, "test", 0))
	switch {
	case m.ErrorLog == nil, m.InfoLog == nil, m.DebugLog == nil:
		t.Errorf("Setting logs failed")
	}
}
