package jwt

import (
	"unsafe"

	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
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

	numPools      = 0x04
	size_pool     = 0x04
	cacheLineSize = unsafe.Sizeof(lowlevelfunctions.CacheLinePadding{})
)

type objectPool[T any] struct {
	// 	"github.com/NikoMalik/low-level-functions/constants"
	_          noCopy
	obj        [][]T
	allocate   func() T
	freeptr    []int32
	currOffset int32
	currChunk  int32
	chunkSize  int32
	cap        int32
}

func (o *objectPool[T]) clear() {

	o.obj = nil
	o.freeptr = nil
	o.currOffset = 0
	o.currChunk = 0
}

func (p *objectPool[T]) _t_(ptr uintptr) *T {
	if ptr == 0 {
		panic("nil pointer dereference")
	}
	return (*T)(unsafe.Pointer(ptr))
}

func (p *objectPool[T]) _u_(v *T) uintptr {
	if v == nil {
		panic("nil pointer dereference")
	}
	return uintptr(unsafe.Pointer(v))
}

func (p *objectPool[T]) malloc() {
	newChunk := make([]T, p.chunkSize)
	for i := range newChunk {
		newChunk[i] = p.allocate()
	}
	p.obj = append(p.obj, newChunk)
}

func newObjPool[T any](cap, chunkSize int32, f func() T) *objectPool[T] {
	if cap <= 0 {
		cap = 1024 // default capacity
	}
	if chunkSize <= 0 {
		chunkSize = 128 // default chunk size
	}

	return &objectPool[T]{
		allocate:   f,
		chunkSize:  chunkSize,
		cap:        cap,
		obj:        make([][]T, 0, cap),
		freeptr:    make([]int32, 0, cap),
		currOffset: 0,
		currChunk:  0,
	}
}

func (o *objectPool[T]) get() T {
	if len(o.freeptr) > 0 {
		idx := o.freeptr[len(o.freeptr)-1]
		o.freeptr = o.freeptr[:len(o.freeptr)-1]

		chunk := idx / o.chunkSize
		offset := idx % o.chunkSize
		return o.obj[chunk][offset]
	}

	if len(o.obj) == 0 || o.currOffset == o.chunkSize {
		o.malloc()
		o.currOffset = 0
		o.currChunk = int32(len(o.obj)) - 1
	}

	obj := o.allocate()
	o.obj[o.currChunk][o.currOffset] = obj
	o.currOffset++
	return obj
}

func (p *objectPool[T]) put(obj T) {
	if int32(len(p.freeptr)) >= p.cap {
		return
	}

	chunk := p.currChunk
	offset := p.currOffset - 1

	p.freeptr = append(p.freeptr, chunk*p.chunkSize+offset)
}

type _oldObjectPool[T any] struct {
	_        noCopy
	obj      []T
	allocate func() T
	cap      int
}

func oldObjPool[T any](cap int, f func() T) *_oldObjectPool[T] {
	pool := &_oldObjectPool[T]{allocate: f}

	if cap < 0 {
		return nil
	}
	if cap <= 0 || cap > MAX_SIZE {
		cap = MAX_SIZE // Cap to a reasonable maximum size
	}

	if cap <= 1 {
		pool.cap = 0x0FFFFFFF
		pool.obj = make([]T, 0, KB)
		// sht := (*reflect.SliceHeader)(unsafe.Pointer(&pool.obj))
		// sht.Cap = KB
		// sht.Len = 0
		// sht.Data = uintptr(unsafe.Pointer(&j))

	} else {
		pool.cap = cap
		pool.obj = make([]T, 0, cap)
		// sht := (*reflect.SliceHeader)(unsafe.Pointer(&pool.obj))

	}

	return pool
}

func (o *_oldObjectPool[T]) get() T {

	if len(o.obj) > 0 {

		obj := o.obj[len(o.obj)-1]
		o.obj = o.obj[:len(o.obj)-1]
		return obj
	}
	return o.allocate() // Create a new object if pool is empty
}
func (o *_oldObjectPool[T]) put(obj T) {
	if len(o.obj) < o.cap {

		o.obj = append(o.obj, obj)
	}
	return

}
