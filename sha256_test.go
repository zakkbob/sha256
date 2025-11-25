package sha256

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func hashString(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

func TestHash(t *testing.T) {
	b := []byte("0000000000000000000000000000000000000000000000000000000000000000000")

	expected := sha256.Sum256(b)
	t.Run("Hash fn", func(t *testing.T) {
		out := Sum(b)
		if out != expected {
			t.Errorf("got %s; expected %s", hashString(out), hashString(expected))
		}
	})
	t.Run("Digest", func(t *testing.T) {
		d := New()
		d.Write(b)
		out := [32]byte(d.Sum([]byte{}))
		if out != expected {
			t.Errorf("got %s; expected %s", hashString(out), hashString(expected))
		}
	})
}

func FuzzHash(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, a []byte) {
		expected := sha256.Sum256(a)
		t.Run("Hash fn", func(t *testing.T) {
			out := Sum(a)
			if out != expected {
				t.Errorf("got %s; expected %s", hashString(out), hashString(expected))
			}
		})
		t.Run("Digest", func(t *testing.T) {
			d := New()
			d.Write(a)
			out := [32]byte(d.Sum([]byte{}))
			if out != expected {
				t.Errorf("got %s; expected %s", hashString(out), hashString(expected))
			}
		})
	})
}

func BenchmarkStdEmptyHash(b *testing.B) {
	for b.Loop() {
		sha256.Sum256([]byte{})
	}
}

func BenchmarkEmptyHash(b *testing.B) {
	for b.Loop() {
		Sum([]byte{})
	}
}

func BenchmarkHashOneBlock(b *testing.B) {
	for b.Loop() {
		b := [55]byte{}
		Sum(b[:])
	}
}

func BenchmarkHashTenBlocks(b *testing.B) {
	for b.Loop() {
		b := [631]byte{}
		Sum(b[:])
	}
}

func BenchmarkHashHundredBlocks(b *testing.B) {
	for b.Loop() {
		b := [6391]byte{}
		Sum(b[:])
	}
}
