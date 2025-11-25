package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/zakkbob/sha256"
)

func hashToString(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

func main() {
	flag.Parse()
	hash := sha256.Sum([]byte(flag.Arg(0)))
	fmt.Print(hashToString(hash))
}
