package sha256

import (
	"fmt"
	"testing"
)

func FuzzSHA256(t *testing.T) {
	data := [0]byte{}
	res := Hash(data[:])
	fmt.Printf("%x%x%x%x%x%x%x%x", res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7])
}
