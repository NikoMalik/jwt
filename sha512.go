package jwt

import (
	"errors"
	"hash"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

var (
	// SHA-512 (init0 to init7)
	init512 = [8]uint64{
		0x6a09e667f3bcc908, // init0
		0xbb67ae8584caa73b, // init1
		0x3c6ef372fe94f82b, // init2
		0xa54ff53a5f1d36f1, // init3
		0x510e527fade682d1, // init4
		0x9b05688c2b3e6c1f, // init5
		0x1f83d9abfb41bd6b, // init6
		0x5be0cd19137e2179, // init7
	}

	// SHA-512/224 (init0_224 to init7_224)
	init512_224 = [8]uint64{
		0x8c3d37c819544da2, // init0_224
		0x73e1996689dcd4d6, // init1_224
		0x1dfab7ae32ff9c82, // init2_224
		0x679dd514582f9fcf, // init3_224
		0x0f6d2b697bd44da8, // init4_224
		0x77e36f7304c48942, // init5_224
		0x3f9d85a86a1d36c8, // init6_224
		0x1112e6ad91d692a1, // init7_224
	}

	// SHA-512/256 (init0_256 to init7_256)
	init512_256 = [8]uint64{
		0x22312194fc2bf72c, // init0_256
		0x9f555fa3c84c64c2, // init1_256
		0x2393b86b6f53b151, // init2_256
		0x963877195940eabd, // init3_256
		0x96283ee2a88effe3, // init4_256
		0xbe5e1e2553863992, // init5_256
		0x2b0199fc2c85b8aa, // init6_256
		0x0eb72ddc81c52ca2, // init7_256
	}

	// SHA-384 (init0_384 to init7_384)
	init384 = [8]uint64{
		0xcbbb9d5dc1059ed8, // init0_384
		0x629a292a367cd507, // init1_384
		0x9159015a3070dd17, // init2_384
		0x152fecd8f70e5939, // init3_384
		0x67332667ffc00b31, // init4_384
		0x8eb44a8768581511, // init5_384
		0xdb0c2e0d64f98fa7, // init6_384
		0x47b5481dbefa4fa4, // init7_384
	}
)

const (
	chunk = 128
	// init0     = 0x6a09e667f3bcc908
	// init1     = 0xbb67ae8584caa73b
	// init2     = 0x3c6ef372fe94f82b
	// init3     = 0xa54ff53a5f1d36f1
	// init4     = 0x510e527fade682d1
	// init5     = 0x9b05688c2b3e6c1f
	// init6     = 0x1f83d9abfb41bd6b
	// init7     = 0x5be0cd19137e2179
	// init0_224 = 0x8c3d37c819544da2
	// init1_224 = 0x73e1996689dcd4d6
	// init2_224 = 0x1dfab7ae32ff9c82
	// init3_224 = 0x679dd514582f9fcf
	// init4_224 = 0x0f6d2b697bd44da8
	// init5_224 = 0x77e36f7304c48942
	// init6_224 = 0x3f9d85a86a1d36c8
	// init7_224 = 0x1112e6ad91d692a1
	// init0_256 = 0x22312194fc2bf72c
	// init1_256 = 0x9f555fa3c84c64c2
	// init2_256 = 0x2393b86b6f53b151
	// init3_256 = 0x963877195940eabd
	// init4_256 = 0x96283ee2a88effe3
	// init5_256 = 0xbe5e1e2553863992
	// init6_256 = 0x2b0199fc2c85b8aa
	// init7_256 = 0x0eb72ddc81c52ca2
	// init0_384 = 0xcbbb9d5dc1059ed8
	// init1_384 = 0x629a292a367cd507
	// init2_384 = 0x9159015a3070dd17
	// init3_384 = 0x152fecd8f70e5939
	// init4_384 = 0x67332667ffc00b31
	// init5_384 = 0x8eb44a8768581511
	// init6_384 = 0xdb0c2e0d64f98fa7
	// init7_384 = 0x47b5481dbefa4fa4

	// size512 is the size, in bytes, of a SHA-512 checksum.
	size512 = 64

	// size224 is the size, in bytes, of a SHA-512/224 checksum.
	size224 = 28

	// size256 is the size, in bytes, of a SHA-512/256 checksum.
	size256 = 32

	// size384 is the size, in bytes, of a SHA-384 checksum.
	size384 = 48

	// blockSize is the block size, in bytes, of the SHA-512/224,
	// SHA-512/256, SHA-384 and SHA-512 hash functions.
	blockSize = 128
)

const (
	magic384      = "sha\x04"
	magic512_224  = "sha\x05"
	magic512_256  = "sha\x06"
	magic512      = "sha\x07"
	marshaledSize = len(magic512) + 8*8 + chunk + 8
)

type digest struct {
	h    [8]uint64
	x    [chunk]byte // chunk 128
	nx   int
	len  uint64
	size int // size224, size256, size384, or size512

}

func (d *digest) Reset() {
	switch d.size {
	case size384:
		d.h[0] = init384[0]
		d.h[1] = init384[1]
		d.h[2] = init384[2]
		d.h[3] = init384[3]
		d.h[4] = init384[4]
		d.h[5] = init384[5]
		d.h[6] = init384[6]
		d.h[7] = init384[7]
	case size224:
		d.h[0] = init512_224[0]
		d.h[1] = init512_224[1]
		d.h[2] = init512_224[2]
		d.h[3] = init512_224[3]
		d.h[4] = init512_224[4]
		d.h[5] = init512_224[5]
		d.h[6] = init512_224[6]
		d.h[7] = init512_224[7]
	case size256:
		d.h[0] = init512_256[0]
		d.h[1] = init512_256[1]
		d.h[2] = init512_256[2]
		d.h[3] = init512_256[3]
		d.h[4] = init512_256[4]
		d.h[5] = init512_256[5]
		d.h[6] = init512_256[6]
		d.h[7] = init512_256[7]
	case size512:
		d.h[0] = init512[0]
		d.h[1] = init512[1]
		d.h[2] = init512[2]
		d.h[3] = init512[3]
		d.h[4] = init512[4]
		d.h[5] = init512[5]
		d.h[6] = init512[6]
		d.h[7] = init512[7]
	default:
		panic("unknown size")
	}
	d.nx = 0
	d.len = 0
}

func _Newi_() hash.Hash {

	d := &digest{size: size512}
	d.Reset()
	return d
}
func (d *digest) Sum(in []byte) []byte {

	// Make a copy of d so that caller can keep writing and summing.
	d0 := new(digest)
	*d0 = *d
	hash := d0.checkSum()

	return append(in, hash[:d.size]...)
}

func (d *digest) Write(p []byte) (nn int, err error) {
	// if d.size != crypto.SHA512_224.Size() && d.size != crypto.SHA512_256.Size() {
	// 	_standart_crypto_without_BoringCrypto()
	// }
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {

		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockAVX2(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockAVX2(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) checkSum() [64]byte {
	// Padding. Add a 1 bit and 0 bits until 112 bytes mod 128.
	len := d.len
	var tmp [128 + 16]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%128 < 112 {
		t = 112 - len%128
	} else {
		t = 128 + 112 - len%128
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+16]
	// Upper 64 bits are always zero, because len variable has type uint64,
	// and tmp is already zeroed at that index, so we can skip updating it.
	// byteorder.BePutUint64(padlen[t+0:], 0)
	BePutUint64(padlen[t+8:], len)
	d.Write(padlen)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [size512]byte
	BePutUint64(digest[0:], d.h[0])
	BePutUint64(digest[8:], d.h[1])
	BePutUint64(digest[16:], d.h[2])
	BePutUint64(digest[24:], d.h[3])
	BePutUint64(digest[32:], d.h[4])
	BePutUint64(digest[40:], d.h[5])
	if d.size != size384 {
		BePutUint64(digest[48:], d.h[6])
		BePutUint64(digest[56:], d.h[7])
	}

	return digest
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	switch {
	case d.size == size384 && lowlevelfunctions.String(b[:len(magic384)]) == magic384:
	case d.size == size224 && lowlevelfunctions.String(b[:len(magic512_224)]) == magic512_224:
	case d.size == size256 && lowlevelfunctions.String(b[:len(magic512_256)]) == magic512_256:
	case d.size == size512 && lowlevelfunctions.String(b[:len(magic512)]) == magic512:
	default:
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]

	b, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func (d *digest) MarshalBinary() ([]byte, error) {
	var s [marshaledSize]byte
	return d.AppendBinary(s[:0])
}

func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	switch d.size {
	case size384:
		b = append(b, magic384...)
	case size224:
		b = append(b, magic512_224...)
	case size256:
		b = append(b, magic512_256...)
	case size512:
		b = append(b, magic512...)
	default:
		panic("unknown size")
	}
	b = BeAppendUint64(b, d.h[0])
	b = BeAppendUint64(b, d.h[1])
	b = BeAppendUint64(b, d.h[2])
	b = BeAppendUint64(b, d.h[3])
	b = BeAppendUint64(b, d.h[4])
	b = BeAppendUint64(b, d.h[5])
	b = BeAppendUint64(b, d.h[6])
	b = BeAppendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-d.nx)...)
	b = BeAppendUint64(b, d.len)
	return b, nil
}

func (d *digest) BlockSize() int { return chunk } // blocksize 128

func (d *digest) Size() int {
	return d.size
}

func _sum512_(data []byte) [64]byte {

	d := &digest{size: size512}
	d.Reset()
	_, _ = d.Write(data)

	return d.checkSum()
}
