package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"testing"
)

func init() {
	verboseLog = log.New(os.Stdout, "verbose : ", 0)
	veryVerboseLog = log.New(os.Stdout, "very verbose : ", 0)
}

func TestCreateFile(t *testing.T) {
	f := createFile(tf)
	defer closeFile(f)
	defer removeTestFile(t, tf)
}

func TestOpenFile(t *testing.T) {
	f := createFile(tf)
	defer closeFile(f)
	defer removeTestFile(t, tf)
	f = openFile(tf)
	defer closeFile(f)
}

func TestCloseFile(t *testing.T) {
	f := createFile(tf)
	defer removeTestFile(t, tf)
	closeFile(f)
}

func TestWriteRead(t *testing.T) {
	f := createFile(tf)
	defer closeFile(f)
	defer removeTestFile(t, tf)
	data := []byte{0x01, 0x02, 0x03}
	writeToFile(f, data...)
	f = openFile(tf) // need to create a new file descriptor
	if out := readFromFile(f); !bytes.Equal(out, data) {
		t.Errorf("File write then read failed with %s", hex.EncodeToString(out))
	}
}
