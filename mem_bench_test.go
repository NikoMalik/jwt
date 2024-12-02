package jwt

import (
	"sync"
	"testing"

	"github.com/NikoMalik/mutex"
)

type MyObject struct {
	ID int
}

func BenchmarkSyncPool(b *testing.B) {
	var pool = sync.Pool{
		New: func() interface{} {
			return MyObject{}
		},
	}

	b.ResetTimer()

	b.Run("Get and Put", func(b *testing.B) {
		obj := pool.Get().(MyObject)
		for i := 0; i < b.N; i++ {
			obj.ID = i
			pool.Put(obj)
		}
	})

	b.Run("Get and Put async", func(b *testing.B) {
		obj := pool.Get().(MyObject)
		for i := 0; i < b.N; i++ {
			go func() {
				obj.ID = i
				pool.Put(obj)
			}()
		}
	})
}

func BenchmarkPoolChan(b *testing.B) {
	pool := NewPoolChan[MyObject](b.N, func() MyObject {

		return MyObject{}

	})
	b.ResetTimer()

	b.Run("Get and Put", func(b *testing.B) {
		obj := pool.Get()
		for i := 0; i < b.N; i++ {
			obj.ID = i
			pool.Put(obj)
		}
	})

	b.Run("Get and Put async", func(b *testing.B) {
		obj := pool.Get()
		for i := 0; i < b.N; i++ {
			go func(i int) {
				obj.ID = i
				pool.Put(obj)
			}(i)
		}
	})
}

func BenchmarkOldPool(b *testing.B) {
	old := nObjPool[MyObject](b.N, func() MyObject {

		return MyObject{}
	})

	b.ResetTimer()
	b.Run("Get and Put", func(b *testing.B) {
		obj := old.Get()
		for i := 0; i < b.N; i++ {
			obj.ID = i
			old.Put(obj)
		}

	})
	old.mut = &mutex.MutexExp{}

	b.Run("Get and Put async", func(b *testing.B) {
		obj := old.Get()
		for i := 0; i < b.N; i++ {
			go func(i int) {
				obj.ID = i
				old.Put(obj)
			}(i)
		}
	})
}
