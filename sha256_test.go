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

func BenchmarkStdEmptyHash(b *testing.B) {
	for b.Loop() {
		sha256.Sum256([]byte{})
	}
}

func BenchmarkEmptyHash(b *testing.B) {
	for b.Loop() {
		Hash([]byte{})
	}
}

func BenchmarkHashOneBlock(b *testing.B) {
	for b.Loop() {
		b := [55]byte{}
		Hash(b[:])
	}
}

func BenchmarkHashTenBlocks(b *testing.B) {
	for b.Loop() {
		b := [631]byte{}
		Hash(b[:])
	}
}

func BenchmarkHashHundredBlocks(b *testing.B) {
	for b.Loop() {
		b := [6391]byte{}
		Hash(b[:])
	}
}
