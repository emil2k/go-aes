package main

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/util/test_files"
	"testing"
)

func TestCreateFile(t *testing.T) {
	f := createFile(test_files.TestOutputFile)
	defer closeFile(f)
	defer removeTestFile(t, test_files.TestOutputFile)
}

func TestOpenFile(t *testing.T) {
	f := createFile(test_files.TestOutputFile)
	defer closeFile(f)
	defer removeTestFile(t, test_files.TestOutputFile)
	f = openFile(test_files.TestOutputFile)
	defer closeFile(f)
}

func TestCloseFile(t *testing.T) {
	f := createFile(test_files.TestOutputFile)
	defer removeTestFile(t, test_files.TestOutputFile)
	closeFile(f)
}

func TestWriteRead(t *testing.T) {
	f := createFile(test_files.TestOutputFile)
	defer closeFile(f)
	defer removeTestFile(t, test_files.TestOutputFile)
	data := []byte{0x01, 0x02, 0x03}
	writeToFile(f, data...)
	f = openFile(test_files.TestOutputFile) // need to create a new file descriptor
	if out := readFromFile(f); !bytes.Equal(out, data) {
		t.Errorf("File write then read failed with %s", hex.EncodeToString(out))
	}
}
