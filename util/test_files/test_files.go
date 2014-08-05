package test_files

import (
	"os"
	"path/filepath"
	"runtime"
)

var TestFilesDir, TestOutputFile, TestFile1MB, TestFile10KB string // absolute path in test files directory.

const (
	testOutput string = "out.test"
	test1MB    string = "1mb.test"
	test10KB   string = "10kb.test"
)

// init determines the absolute path of test files directory, assuming it is in the
// same directory as this file then determines the paths of the test files.
func init() {
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		panic("Could not determine test file directory")
	}
	if path, err := filepath.Abs(file); err != nil {
		panic(err.Error())
	} else {
		// Initialize paths.
		TestFilesDir = filepath.Dir(path)
		TestOutputFile = filepath.Join(TestFilesDir, testOutput)
		TestFile1MB = filepath.Join(TestFilesDir, test1MB)
		TestFile10KB = filepath.Join(TestFilesDir, test10KB)
	}
}

// Open1MBTestFile opens a 1MB test file in read only mode.
func Open1MBTestFile() (*os.File, error) {
	return os.Open(TestFile1MB)
}

// Open10KBTestFile opens a 10KB test file in read only mode.
func Open10KBTestFile() (*os.File, error) {
	return os.Open(TestFile10KB)
}
