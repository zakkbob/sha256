package sha256

import "encoding/binary"

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

func rotateRight(b uint32, n int) uint32 {
	n %= 32
	return (b >> n) | (b << (32 - n))
}

func toBytes(h [8]uint32) [32]byte {
	var b [32]byte

	binary.BigEndian.PutUint32(b[0:4], h[0])
	binary.BigEndian.PutUint32(b[4:8], h[1])
	binary.BigEndian.PutUint32(b[8:12], h[2])
	binary.BigEndian.PutUint32(b[12:16], h[3])
	binary.BigEndian.PutUint32(b[16:20], h[4])
	binary.BigEndian.PutUint32(b[20:24], h[5])
	binary.BigEndian.PutUint32(b[24:28], h[6])
	binary.BigEndian.PutUint32(b[28:32], h[7])

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

func New() Digest {
	d := Digest{}
	d.Reset()
	return d
}

type Digest struct {
	h [8]uint32

	count int // number of bytes written
	block [64]byte
	i     int // index of next byte to write to block
}

func (d *Digest) Write(p []byte) (n int, err error) {
	for _, b := range p {
		d.block[d.i] = b
		d.i++
		d.count++

		if d.i == 64 {
			d.i = 0
			d.processBlock()
		}
	}

	return len(p), nil
}

func (d *Digest) Sum(b []byte) []byte {
	var c Digest
	c = *d

	c.block[c.i] = 0b10000000
	c.i++
	if c.i == 64 {
		c.i = 0
		c.processBlock()
	}

	for i := range 64 - c.i {
		c.block[c.i+i] = 0
	}

	if c.i > 56 {
		c.processBlock()
		for i := range c.i {
			c.block[i] = 0
		}
	}

	bits := uint64(d.count) * 8
	c.block[56] = byte(bits & 0b1111111100000000000000000000000000000000000000000000000000000000 >> 56)
	c.block[57] = byte(bits & 0b0000000011111111000000000000000000000000000000000000000000000000 >> 48)
	c.block[58] = byte(bits & 0b0000000000000000111111110000000000000000000000000000000000000000 >> 40)
	c.block[59] = byte(bits & 0b0000000000000000000000001111111100000000000000000000000000000000 >> 32)
	c.block[60] = byte(bits & 0b0000000000000000000000000000000011111111000000000000000000000000 >> 24)
	c.block[61] = byte(bits & 0b0000000000000000000000000000000000000000111111110000000000000000 >> 16)
	c.block[62] = byte(bits & 0b0000000000000000000000000000000000000000000000001111111100000000 >> 8)
	c.block[63] = byte(bits & 0b0000000000000000000000000000000000000000000000000000000011111111)

	c.processBlock()

	h := toBytes(c.h)
	b = append(b, h[:]...)
	return b
}

func (d *Digest) Reset() {
	d.h = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	d.count = 0
	d.i = 0
}

func (d *Digest) Size() int {
	return 256
}

func (d *Digest) BlockSize() int {
	return 512
}

func Sum(data []byte) [32]byte {
	d := New()
	d.Write(data)
	return [32]byte(d.Sum([]byte{}))
}

func (d *Digest) processBlock() {
	var schedule [64]uint32

	for t := range 64 {
		if t <= 15 {
			j := t * 4
			schedule[t] = (uint32(d.block[j]) << 24) | (uint32(d.block[j+1]) << 16) | (uint32(d.block[j+2]) << 8) | uint32(d.block[j+3])
			continue
		}
		schedule[t] = lilSigmaOne(schedule[t-2]) + schedule[t-7] + lilSigmaZero(schedule[t-15]) + schedule[t-16]
	}

	a := d.h[0]
	b := d.h[1]
	c := d.h[2]
	d1 := d.h[3]
	e := d.h[4]
	f := d.h[5]
	g := d.h[6]
	h := d.h[7]

	for t := range 64 {
		temp1 := h + bigSigmaOne(e) + ch(e, f, g) + k[t] + schedule[t]
		temp2 := bigSigmaZero(a) + maj(a, b, c)
		h = g
		g = f
		f = e
		e = d1 + temp1
		d1 = c
		c = b
		b = a
		a = temp1 + temp2

	}

	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += d1
	d.h[4] += e
	d.h[5] += f
	d.h[6] += g
	d.h[7] += h
}
