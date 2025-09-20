package sha256

const BlockSize = 512
const WordSize = 32

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func rotateLeft(b uint32, n int) uint32 {
	n %= 32
	return (b << n) | (b >> (32 - n))
}

func rotateRight(b uint32, n int) uint32 {
	n %= 32
	return (b >> n) | (b << (32 - n))
}

func process(data []byte) []byte {
	bits := uint64(len(data)) * 8
	freeBytes := 64 - len(data)%64

	zeroBytes := freeBytes - 1 - 8
	if freeBytes < 9 {
		zeroBytes += 64
	}

	data = append(data, 0b10000000)
	for range zeroBytes {
		data = append(data, 0b00000000)
	}

	data = append(data, byte(bits&0b1111111100000000000000000000000000000000000000000000000000000000>>56))
	data = append(data, byte(bits&0b0000000011111111000000000000000000000000000000000000000000000000>>48))
	data = append(data, byte(bits&0b0000000000000000111111110000000000000000000000000000000000000000>>40))
	data = append(data, byte(bits&0b0000000000000000000000001111111100000000000000000000000000000000>>32))
	data = append(data, byte(bits&0b0000000000000000000000000000000011111111000000000000000000000000>>24))
	data = append(data, byte(bits&0b0000000000000000000000000000000000000000111111110000000000000000>>16))
	data = append(data, byte(bits&0b0000000000000000000000000000000000000000000000001111111100000000>>8))
	data = append(data, byte(bits&0b0000000000000000000000000000000000000000000000000000000011111111))

	return data
}

func toWords(data []byte) []uint32 {
	var words []uint32
	for i := 0; i < len(data); i += 4 {
		var word uint32
		word |= uint32(data[i]) << 24
		word |= uint32(data[i+1]) << 16
		word |= uint32(data[i+2]) << 8
		word |= uint32(data[i+3])
		words = append(words, word)
	}
	return words
}

func toBytes(words []uint32) []byte {
	var b []byte
	for _, w := range words {
		b = append(b, byte(w&0b11111111000000000000000000000000>>24))
		b = append(b, byte(w&0b00000000111111110000000000000000>>16))
		b = append(b, byte(w&0b00000000000000001111111100000000>>8))
		b = append(b, byte(w&0b00000000000000000000000011111111))
	}
	return b
}

func bigSigmaZero(n uint32) uint32 {
	return rotateRight(n, 2) ^ rotateRight(n, 13) ^ rotateRight(n, 22)
}

func bigSigmaOne(n uint32) uint32 {
	return rotateRight(n, 6) ^ rotateRight(n, 11) ^ rotateRight(n, 25)
}

func lilSigmaZero(n uint32) uint32 {
	return rotateRight(n, 7) ^ rotateRight(n, 18) ^ (n >> 3)
}

func lilSigmaOne(n uint32) uint32 {
	return rotateRight(n, 17) ^ rotateRight(n, 19) ^ (n >> 10)
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ ((^x) & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func Hash(data []byte) [32]byte {
	var schedule [64]uint32
	var a, b, c, d, e, f, g, h uint32
	hash := [8]uint32{
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}

	data = process(data)
	msg := toWords(data)

	blocks := len(msg) * 32 / 512

	for i := range blocks {
		for t := range 64 {
			if t <= 15 {
				schedule[t] = msg[t+i*32]
				continue
			}
			schedule[t] = lilSigmaOne(schedule[t-2]) + schedule[t-7] + lilSigmaZero(schedule[t-15]) + schedule[t-16]
		}

		a = hash[0]
		b = hash[1]
		c = hash[2]
		d = hash[3]
		e = hash[4]
		f = hash[5]
		g = hash[6]
		h = hash[7]

		for t := range 64 {
			temp1 := h + bigSigmaOne(e) + ch(e, f, g) + k[t] + schedule[t]
			temp2 := bigSigmaZero(a) + maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2

		}

		hash[0] += a
		hash[1] += b
		hash[2] += c
		hash[3] += d
		hash[4] += e
		hash[5] += f
		hash[6] += g
		hash[7] += h
	}

	return [32]byte(toBytes(hash[:]))

}
