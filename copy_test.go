package jwt

import (
	"reflect"
	"testing"
)

func Test_Copy(t *testing.T) {

	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dest := []byte{0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11}

	t.Run("Standard copy", func(t *testing.T) {

		copy(src, dest)
		if !reflect.DeepEqual(src, dest) {
			t.Errorf("Standard copy failed: expected %v, got %v", src, dest)
		}
	})

	t.Run("Custom copy", func(t *testing.T) {

		_copy_(src, dest)
		if !reflect.DeepEqual(src, dest) {
			t.Errorf("Custom copy failed: expected %v, got %v", src, dest)
		}
	})
}
