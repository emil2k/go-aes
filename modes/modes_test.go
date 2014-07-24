package modes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAddPadding(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	m := NewMode(nil)
	m.In = in
	if m.AddPadding(); !bytes.Equal(m.In, out) {
		t.Errorf("Adding padding failed with %s", hex.EncodeToString(m.In))
	}
}

func TestRemovePadding(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97}
	m := NewMode(nil)
	m.Out = in
	if m.RemovePadding(); !bytes.Equal(m.Out, out) {
		t.Errorf("Remove padding failed with %s", hex.EncodeToString(m.Out))
	}
}

func TestNonce(t *testing.T) {
	n := 100
	nonce, _ := NewNonce(n)
	if len(nonce) != n {
		t.Errorf("Nonce is not %d bytes long", n)
	} else if bytes.Equal(nonce, make([]byte, n)) {
		t.Errorf("Nonce is all zero value bytes, something probably wrong")
	}
}

func TestGetBlock(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	for i := 0; i < 32; i++ {
		in = append(in, 0x00)
	}
	m := Mode{In: in}
	if b := m.GetBlock(0); !bytes.Equal(b, out) {
		t.Errorf("Get block failed with %s", hex.EncodeToString(b))
	}
}
