package jwt

import (
	"reflect"
	"testing"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

var (
	testSizes = [...]int{
		0, 1, 2, 3, 4, 6, 8, 10, 31, 32, 33, 64, 100, //1024,4096
	}
)

func Test_Copy(t *testing.T) {

	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dest := []byte{0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11}

	src_1 := make([]byte, 16)
	dest_1 := []byte{
		22, 22, 22, 22, 22, 22, 22, 22,
		22, 22, 22, 22, 22, 22, 22, 22,
	}

	t.Run("Standard copy", func(t *testing.T) {

		copy(src, dest)
		if !reflect.DeepEqual(src, dest) {
			t.Errorf("Standard copy failed: expected %v, got %v", src, dest)
		}
		// t.Log(src)
	})

	t.Run("Custom copy", func(t *testing.T) {

		_copy_(src, dest)
		if !reflect.DeepEqual(src, dest) {
			t.Errorf("Custom copy failed: expected %v, got %v", src, dest)
		}
		// t.Log(src)
	})
	t.Run("Standard copy 2", func(t *testing.T) {

		copy(src_1, dest_1)
		if !reflect.DeepEqual(src_1, dest_1) {
			t.Errorf("Standard copy failed: expected %v, got %v", src_1, dest_1)
		}
		// t.Log(src_1)

	})

	t.Run("Custom copy 2", func(t *testing.T) {

		_copy_(src_1, dest_1)
		if !reflect.DeepEqual(src, dest) {
			t.Errorf("Custom copy failed: expected %v, got %v", src, dest)
		}
		// t.Log(src_1)
	})
	t.Run("Standard copy 3", func(t *testing.T) {
		p := []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		}

		var publicKey = lowlevelfunctions.MakeNoZero(32)
		// fmt.Println(len(publicKey))
		copy(publicKey, p[32:])

		if !reflect.DeepEqual(publicKey, p[32:]) {
			t.Errorf("Standard copy failed: expected %v, got %v", p[32:], publicKey)
		}

		// t.Log(p[32:])

	})
	// t.Run("Custom copy 3", func(t *testing.T) {
	// 	p := []byte{
	// 		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	// 		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	// 		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	// 		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	// 		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	// 		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	// 		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	// 		0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
	// 	}
	// 	var publicKey = lowlevelfunctions.MakeNoZero(32)
	// 	// fmt.Println(len(publicKey))
	// 	_copy_(publicKey, p[32:])
	//
	// 	if !reflect.DeepEqual(publicKey, p[32:]) {
	// 		t.Errorf("Standard copy failed: expected %v, got %v", p[32:], publicKey)
	// 	}
	//
	// 	t.Log(p[32:])
	//
	// })

	t.Run("avx2 copy", func(t *testing.T) {

		p := []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		}

		var publicKey = make([]byte, 32)
		// fmt.Println(len(publicKey))
		copy_AVX2_32(publicKey, p)

		if !reflect.DeepEqual(publicKey, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, publicKey)
		}

		// t.Log(publicKey)

	})

	t.Run("avx2 copy 64", func(t *testing.T) {

		p := []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		}

		s := make([]byte, 64)

		copy_AVX2_64(s, p)

		if !reflect.DeepEqual(s, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		// t.Log(s)
	})

	t.Run("avx2 copy 128", func(t *testing.T) {
		p := []byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2, 3, 4, 5, 6, 7, 8, 9,
			1, 2,
		}

		s := make([]byte, 128)

		copy_AVX2_128(s, p)

		if !reflect.DeepEqual(s, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		// t.Log(s)
	})

	t.Run("avx2 copy 64: 32 to 64 ", func(t *testing.T) {

		p := []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		}

		s := make([]byte, 64)

		copy_AVX2_64(s[:32], p)

		if !reflect.DeepEqual(s[:32], p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		t.Log(s)

	})

	t.Run("avx2 copy more 512", func(t *testing.T) {
		p := make([]byte, 512)
		for i := 0; i < len(p); i++ {
			p[i] = byte(i)
		}

		s := make([]byte, 512)

		copy_AVX2_512(s, p)

		if !reflect.DeepEqual(s, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		// t.Log("s", s)

	})

	t.Run("avx2 copy 256 ", func(t *testing.T) {
		p := make([]byte, 256)

		for i := range p {
			p[i] = byte(i)
		}

		s := make([]byte, 256)

		copy_AVX2_256(s, p)

		if !reflect.DeepEqual(s, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		// t.Log(s)

	})

	t.Run("avx2 copy more 1024", func(t *testing.T) {
		p := make([]byte, 1024)

		for i := range p {
			p[i] = byte(i)
		}

		s := make([]byte, 1024)

		copy_AVX2_1024(s, p)

		if !reflect.DeepEqual(s, p) {
			t.Errorf("avx copy failed: expected %v, got %v", p, s)
		}

		// t.Log(s)

	})

}
