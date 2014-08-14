package bytes

import (
	"io"
)

// ReadWriteSeeker wraps a byte slice providing Reader, Writer, and Seeker
// interfaces for testing purposes.
type ReadWriteSeeker struct {
	pos  int    // current positon of seeker
	data []byte // data
	ilen int    // initial data length
	icap int    // initial data capacity
}

// NewReadWriteSeeker creates a new instance
func NewReadWriteSeeker(data []byte) *ReadWriteSeeker {
	return &ReadWriteSeeker{
		pos:  0,
		data: data,
		ilen: len(data),
		icap: cap(data),
	}
}

// Bytes returns a slice representing the underlying data.
func (b *ReadWriteSeeker) Bytes() []byte {
	return b.data
}

// Position returns the current index, from which it will read or write to the next request.
func (b *ReadWriteSeeker) Position() int {
	return b.pos
}

// Truncate empties the underlying data back to the original size and capacity.
func (b *ReadWriteSeeker) Truncate() {
	b.data = make([]byte, b.ilen, b.icap)
}

// Read reads into the dst slice from the underlying slice.
// Returns io.EOF error when nothing can be read, with `n` always equal to 0.
func (b *ReadWriteSeeker) Read(dst []byte) (n int, err error) {
	if b.pos >= len(b.data) {
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

// Write writes the given bytes to the underlying slice, returns the number of bytes written.
// Grows underlying slice if necessary.
func (b *ReadWriteSeeker) Write(src []byte) (n int, err error) {
	var start, end int = b.pos, b.pos + len(src)
	if end > len(b.data) {
		b.data = append(b.data, make([]byte, end-len(b.data))...)
	}
	n = copy(b.data[start:], src)
	b.pos += n
	return
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
