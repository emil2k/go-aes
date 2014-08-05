package main

import "os"
import "testing"

// removeTestFile used in tests to remove a temporary test files
// fails test if there is a problem removing the test file
func removeTestFile(t *testing.T, name string) {
	if err := os.Remove(name); err != nil {
		t.Errorf("Error while removing test file : %s", err.Error())
	}
}
