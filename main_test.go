package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"testing"
)

func init() {
	verboseLog = log.New(os.Stdout, "debug : ", 0)
	veryVerboseLog = log.New(os.Stdout, "debug : ", 0)
}

// mockExecute
func mockExecute(args ...string) {
	flag.CommandLine = flag.NewFlagSet("go-aes", flag.ExitOnError) // reset the flag set
	os.Args = []string{"go-aes"}
	os.Args = append(os.Args, args...)
	prepareFlags()
	main()
}

// testModeEncryptDecrypt setups and runs a encrypt/decrypt cycle using the given mode
// checking that the decryption is the inverse of encryption
func testModeEncryptDecrypt(t *testing.T, mode string) {
	// Prepare file to encrypt
	data := []byte{0x01, 0x02, 0x03}
	f := createFile(tf)
	defer closeFile(f)
	defer removeTestFile(t, tf)
	writeToFile(f, data...)
	// Encrypt file
	key := tf + ".key"
	encrypted := tf + ".aes"
	defer removeTestFile(t, key)
	defer removeTestFile(t, encrypted)
	mockExecute("-vv", "-mode", mode, key, tf, encrypted)
	// Decrypt file
	out := tf + ".out"
	defer removeTestFile(t, out)
	mockExecute("-vv", "-d", "-mode", mode, key, encrypted, out)
	// Inspect output
	of := openFile(out)
	defer closeFile(of)
	outData := readFromFile(of)
	if !bytes.Equal(outData, data) {
		t.Errorf("Encrypt the decrypt failed with %s", hex.EncodeToString(outData))
	}
}

func TestCTRMode(t *testing.T) {
	testModeEncryptDecrypt(t, "ctr")
}
