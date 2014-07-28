package bytes

import (
	"io"
)

// ReadWriteSeeker wraps a byte slice providing Reader, Writer, and Seeker
// interfaces for testing purposes.
type ReadWriteSeeker struct {
	pos  int    // current positon of seeker
	data []byte // data
}

// NewReadWriteSeeker creates a new instance
func NewReadWriteSeeker(data []byte) *ReadWriteSeeker {
	return &ReadWriteSeeker{
		pos:  0,
		data: data,
	}
}

// Read reads into the dst slice from the underlying slice.
// Returns io.EOF error when there is nothing more to read.
func (b *ReadWriteSeeker) Read(dst []byte) (n int, err error) {
	if b.pos == len(b.data) {
		return 0, io.EOF
	}
	if ext := b.pos + len(dst); ext > len(b.data) {
		copy(dst, b.data[b.pos:])
		n = len(b.data) - b.pos
		b.pos = len(b.data)
	} else {
		copy(dst, b.data[b.pos:b.pos+len(dst)])
		n = len(dst)
		b.pos += len(dst)
	}
	return n, nil
}

func (b *ReadWriteSeeker) Write(src []byte) (n int, err error) {
	copy(b.data[b.pos:b.pos+len(src)], src)
	b.pos += len(src)
	return len(src), nil
}

func (b *ReadWriteSeeker) Seek(offset int64, whence int) (n int64, err error) {
	switch whence {
	case 0:
		b.pos = int(offset)
	case 1:
		b.pos = b.pos + int(offset)
	case 2:
		b.pos = len(b.data) - int(offset)
	}
	return int64(b.pos), nil
}
