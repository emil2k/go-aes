package bytes

import (
	obytes "bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/util/rand"
	"io"
	"testing"
)

// TestSeekRead tests a seek and then read, to retrieve all requested bytes.
func TestSeekRead(t *testing.T) {
	data := rand.GetRand(3)
	rw := NewReadWriteSeeker(data)
	rw.Seek(1, 0)
	out := data[1:3] // expected output
	b := make([]byte, 2)
	rw.Read(b)
	if !obytes.Equal(b, out) {
		t.Errorf("Seek read failed with %s", hex.EncodeToString(b))
	}
}

// TestReadIncomplete tests a read that is shorther then the destination slice.
// Will be attempting to read 5 bytes when there is only 2 bytes in the underlying slice.
func TestReadIncomplete(t *testing.T) {
	data := rand.GetRand(2)
	rw := NewReadWriteSeeker(data)
	out := make([]byte, 5)
	copy(out, data)      // expected output
	b := make([]byte, 5) // asking for 5 bytes, but there is only 2 bytes
	n, err := rw.Read(b)
	switch {
	case n != len(data):
		t.Errorf("Read incorrect amount of bytes %d", n)
	case err != nil:
		t.Errorf("Unexpected error while performing incomplete read %s", err.Error())
	case !obytes.Equal(b, out):
		t.Errorf("Incomplete read failed with %s", hex.EncodeToString(b))
	}
}

// TestReadEOF tests the end of the read that should return 0 bytes read and an io.EOF error.
// Will request 5 bytes, none of them should change.
func TestReadEOF(t *testing.T) {
	data := []byte{}
	rw := NewReadWriteSeeker(data)
	out := make([]byte, 5) // expected output
	b := make([]byte, 5)
	n, err := rw.Read(b)
	switch {
	case n != 0:
		t.Errorf("Read %d bytes, should have been 0", n)
	case err != io.EOF:
		t.Errorf("No io.EOF error received")
	case !obytes.Equal(b, out):
		t.Errorf("EOF read failed with %s", hex.EncodeToString(b))
	}
}

// TestSeekWrite test a seek and the write to the underlying byte slice.
func TestSeekWrite(t *testing.T) {
	data := rand.GetRand(3)
	write := rand.GetRand(2)
	rw := NewReadWriteSeeker(data)
	out := make([]byte, 3)
	copy(out, data[0:1])
	copy(out[1:3], write) // expected output
	rw.Seek(1, 0)
	n, err := rw.Write(write)
	switch {
	case n != len(write):
		t.Errorf("Wrote %d bytes, should have been %d", n, len(write))
	case err != nil:
		t.Errorf("Unexpected error during seek write %s", err.Error())
	case !obytes.Equal(rw.data, out):
		t.Errorf("Seek write failed with %s", hex.EncodeToString(rw.data))
	}

}

func TestWriteExtend(t *testing.T) {
	w := NewReadWriteSeeker(make([]byte, 0)) // 0 byte slice which will need to extend
	w.pos = 2
	in := []byte{0x01, 0x02, 0x03}
	out := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
	n, err := w.Write(in)
	if n != 3 {
		t.Errorf("Write extend failed returned wrong bytes written.")
	} else if err != nil {
		t.Errorf("Unexpected error reported during write : %s", err.Error())
	} else if b := w.Bytes(); !obytes.Equal(b, out) {
		t.Errorf("Written data %s does not match input %s", hex.EncodeToString(b), hex.EncodeToString(out))
	}
}
