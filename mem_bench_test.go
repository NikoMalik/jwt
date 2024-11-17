package jwt

import (
	"sync"
	"testing"
)

type MyObject struct {
	ID int
}

func BenchmarkCustomPool(b *testing.B) {
	pool := newObjPool[MyObject](1024, 128, func() MyObject {

		return MyObject{}
	})
	b.ResetTimer()

	b.Run("Get and Put", func(b *testing.B) {
		obj := pool.get()
		for i := 0; i < b.N; i++ {
			obj.ID = i
			pool.put(obj)
		}
	})
}

func BenchmarkSyncPool(b *testing.B) {
	var pool = sync.Pool{
		New: func() interface{} {
			return MyObject{}
		},
	}

	b.ResetTimer()

	b.Run("Get and Put", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			obj := pool.Get().(MyObject)
			obj.ID = i
			pool.Put(obj)
		}
	})
}
