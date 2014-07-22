package main

import "bytes"
import "encoding/hex"
import "flag"
import "testing"
import "os"

// mockExecute
func mockExecute(args ...string) {
	flag.CommandLine = flag.NewFlagSet("go-aes", flag.ExitOnError) // reset the flag set
	os.Args = []string{"go-aes"}
	os.Args = append(os.Args, args...)
	main()
}

func TestEncryptDecrypt(t *testing.T) {
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
	mockExecute("-vv", key, tf, encrypted)
	// Decrypt file
	out := tf + ".out"
	defer removeTestFile(t, out)
	mockExecute("-v", "-d", key, encrypted, out)
	// Inspect output
	of := openFile(out)
	defer closeFile(of)
	outData := readFromFile(of)
	if !bytes.Equal(outData, data) {
		t.Errorf("Encrypt the decrypt failed with %s", hex.EncodeToString(outData))
	}
}
