package jwt

import (
	"unsafe"
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

	numPools = 0x04
	size     = 0x04
)

func alignSize(size, align int) int {
	return (size + align - 1) &^ (align - 1) // Align to the nearest boundary
}

type objectPool[T any] struct {
	_          noCopy
	obj        [][5]T
	freeptr    []uintptr
	allocate   func() T
	currOffset int
	currChunk  int
	cap        int
}

func (o *objectPool[T]) clear() {

	o.obj = nil
	o.freeptr = nil
	o.currOffset = 0
	o.currChunk = 0
}

//go:noinline
func (p *objectPool[T]) _t_(ptr uintptr) *T {
	return (*T)(unsafe.Pointer(ptr))
}

//go:noinline
func (p *objectPool[T]) _u_(v *T) uintptr {
	return uintptr(unsafe.Pointer(v))
}

func (p *objectPool[T]) malloc() {
	p.obj = append(p.obj, [5]T{})
}

func newObjPool[T any](cap int, f func() T) *objectPool[T] {
	pool := &objectPool[T]{allocate: f}

	if cap < 0 {
		return nil
	}
	if cap <= 0 || cap > MAX_SIZE {
		cap = MAX_SIZE // Cap to a reasonable maximum size
	}

	if cap < 1 {
		pool.cap = 0x0FFFFFFF
		pool.obj = make([][5]T, 0, KB)
		pool.freeptr = make([]uintptr, 0, KB)

	} else {
		pool.cap = cap
		pool.obj = make([][5]T, 0, pool.cap)
		pool.freeptr = make([]uintptr, 0, pool.cap)
		// pool.obj = make([]T, 0, alignSize(cap, B_8))

	}
	return pool
}

func (o *objectPool[T]) get() T {
	if len(o.freeptr) != 0 {
		ptr := o.freeptr[len(o.freeptr)-1]
		o.freeptr = o.freeptr[:len(o.freeptr)-1]
		return *o._t_(ptr)
	}
	st := o.allocate()
	if len(o.obj) == 0 {
		o.malloc()

	}
	if o.currOffset == len(o.obj[o.currChunk]) {
		o.malloc()
		o.currOffset = 0x0
		o.currChunk++
	}

	// safe object in current chunk
	// ptr := unsafe.Pointer(&st)

	__bb__ := *(*[5]T)(unsafe.Pointer(&st))
	for i := 0; i < 5; i++ {
		o.obj[o.currChunk][o.currOffset+i] = __bb__[i]
	}
	o.currOffset += 5

	return *(*T)(unsafe.Pointer(&o.obj[o.currChunk][o.currOffset-5]))

}
func (o *objectPool[T]) put(obj T) {
	if len(o.obj) >= o.cap {
		return
	}

	o.freeptr = append(o.freeptr, o._u_(&obj))
}
