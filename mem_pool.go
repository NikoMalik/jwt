package jwt

import (
	"sync/atomic"
	"unsafe"

	"github.com/NikoMalik/low-level-functions/constants"
	"github.com/NikoMalik/mutex"
)

const (
	KB    = 1 << 10  // 1KB
	KB_32 = 32 << 10 // 32KB
	MB    = 1 << 20  // 1MB
	MB_32 = 32 << 20 // 32MB
	GB    = 1 << 30  // 1GB
	GB_32 = 32 << 30 // 32GB

	B_8      = 8         // 8B
	B_256    = 256       // 256B
	KB_8     = 8 << 10   // 8KB
	KB_256   = 256 << 10 // 256KB
	MB_8     = 8 << 20   // 8MB
	MAX_SIZE = GB        // Maximum allowed size

	numPools  = 0x04
	size_pool = 0x04
)

type PoolChan[T any] struct {
	_ noCopy
	c [1]atomic.Pointer[T]

	new func() T
	_   [constants.CacheLinePadSize - unsafe.Sizeof(func() any { return nil })]byte
}

func NewPoolChan[T any](size int, new func() T) *PoolChan[T] {
	if size <= 0 {
		panic("size must be greater than 0")
	}
	pool := &PoolChan[T]{
		c:   [1]atomic.Pointer[T]{},
		new: new,
	}
	// for i := 0; i < size; i++ {
	// 	pool.c[i].Store(nil)
	// }

	return pool
}

func (p *PoolChan[T]) Get() T {
	for i := uint32(0); i < 1; i++ {
		ptr := p.c[i].Load()
		if ptr != nil {

			if p.c[i].CompareAndSwap(ptr, nil) {
				return *ptr
			}
		}
	}

	return p.new()
}

func (p *PoolChan[T]) Put(obj T) {
	for i := uint32(0); i < 1; i++ {
		if p.c[i].CompareAndSwap(nil, &obj) {
			return
		}
	}
}

func (p *PoolChan[T]) CurrentSize() int {
	size := 0
	for i := uint32(0); i < 1; i++ {
		ptr := p.c[i].Load()
		if ptr != nil {
			size++
		}
	}
	return size
}

type objPool[T any] struct {
	mut      *mutex.MutexExp
	_        [constants.CacheLinePadSize - 8]byte
	obj      []T
	_        [constants.CacheLinePadSize - unsafe.Sizeof([]T{})]byte
	allocate func() T
	_        [constants.CacheLinePadSize - unsafe.Sizeof(func() T { var z T; return z })]byte
	size     int
	_        [constants.CacheLinePadSize - unsafe.Sizeof(int(0))]byte
}

func nObjPool[T any](capt int, f func() T) *objPool[T] {

	pool := &objPool[T]{allocate: f}

	if capt < 0 {
		return nil
	}

	pool.size = capt
	pool.obj = make([]T, 0, capt)

	return pool
}

func (o *objPool[T]) Get() T {
	if len(o.obj) <= 0 {
		return o.allocate()

	}
	if o.mut == nil {

		obj := o.obj[len(o.obj)-1]
		o.obj = o.obj[:len(o.obj)-1]
		return obj

	}
	if o.mut != nil {
		o.mut.Lock()
		obj := o.obj[len(o.obj)-1]
		o.obj = o.obj[:len(o.obj)-1]

		o.mut.Unlock()
		return obj
	}
	var zero T
	return zero

}

func (o *objPool[T]) Put(obj T) {
	if o.mut != nil {
		o.mut.Lock()
		if len(o.obj) < o.size {

			o.obj = append(o.obj, obj)
		}

		o.mut.Unlock()
	}
	if o.mut == nil {

		if len(o.obj) < o.size {

			o.obj = append(o.obj, obj)
		}
	}
}
