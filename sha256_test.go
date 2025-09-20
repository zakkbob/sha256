package sha256

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func hashString(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

func FuzzHash(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, a []byte) {
		out := Hash(a)
		expected := sha256.Sum256(a)
		if out != expected {
			t.Errorf("got %s; expected %s", hashString(out), hashString(expected))
		}
	})
}
