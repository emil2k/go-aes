package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"github.com/emil2k/go-aes/util/test_files"
	"log"
	"os"
	"testing"
)

func init() {
	verboseLog = log.New(os.Stdout, "debug : ", 0)
	veryVerboseLog = log.New(os.Stdout, "debug : ", 0)
}

// mockExecute emulates a command execution.
func mockExecute(args ...string) {
	flag.CommandLine = flag.NewFlagSet("go-aes", flag.ExitOnError) // reset the flag set
	os.Args = []string{"go-aes"}
	os.Args = append(os.Args, args...)
	prepareFlags()
	main()
}

// testModeEncryptDecrypt setups and runs a mock command call to encrypt/decrypt cycle using
// the given mode checking that the decryption is the inverse of encryption.
// Outputs to test files, which are cleaned up afterward.
func testModeEncryptDecrypt(t *testing.T, mode string) {
	// Prepare file to encrypt
	f, err := test_files.Open10KBTestFile()
	defer closeFile(f)
	if err != nil {
		panic(err.Error())
	}
	data := readFromFile(f)
	// Encrypt file
	key := test_files.TestFile10KB + ".key"
	encrypted := test_files.TestFile10KB + ".aes"
	defer removeTestFile(t, key)
	defer removeTestFile(t, encrypted)
	mockExecute("-vv", "-mode", mode, key, f.Name(), encrypted)
	// Decrypt file
	out := test_files.TestOutputFile
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

func TestCBCMode(t *testing.T) {
	testModeEncryptDecrypt(t, "cbc")
}
