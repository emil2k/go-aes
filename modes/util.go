package modes

import (
	"bytes"
	"encoding/hex"
	mbytes "github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/util/rand"
	"github.com/emil2k/go-aes/util/test_files"
	"os"
	"testing"
)

// EncryptDecryptTest generates and encrypt decrypt test using the passed mode instance.
// The test simply tests if decryption is the inverse of encryption.
func EncryptDecryptTest(t *testing.T, mode ModeInterface, ck []byte, nonce []byte) {
	data := rand.GetRand(int(BlockSize) * 5 / 2) // partial block to test padding and unpadding
	expected := make([]byte, len(data))
	copy(expected, data)
	// Setup input for encryption
	in := bytes.NewReader(data)
	out := mbytes.NewReadWriteSeeker(make([]byte, 0))
	mode.Encrypt(0, uint64(len(data)), in, out, ck, nonce)
	// Setup input for decryption
	dData := out.Bytes()
	dIn := bytes.NewReader(dData)
	dOut := mbytes.NewReadWriteSeeker(make([]byte, 0))
	mode.Decrypt(0, uint64(len(dData)), dIn, dOut, ck, nonce)
	if x := dOut.Bytes(); !bytes.Equal(x, expected) {
		t.Errorf("Encryption followed by decryption failed with %s", hex.EncodeToString(x))
	}
}

// EncryptBenchmark generates and runs a benchmark for encryption using the passed mode instance.
func EncryptBenchmark(b *testing.B, mode ModeInterface, ck []byte, nonce []byte) {
	b.ResetTimer()
	run := func() {
		b.StopTimer()
		in, err := test_files.Open1MBTestFile()
		defer in.Close()
		if err != nil {
			panic(err.Error())
		}
		var size uint64
		if fi, err := in.Stat(); err != nil {
			panic(err.Error())
		} else {
			size = uint64(fi.Size())
		}
		out, err := os.Create(test_files.TestOutputFile)
		defer out.Close()
		if err != nil {
			panic(err.Error())
		}
		b.StartTimer()
		mode.Encrypt(0, size, in, out, ck, nonce)
	}
	for i := 0; i < b.N; i++ {
		run()
	}
}
