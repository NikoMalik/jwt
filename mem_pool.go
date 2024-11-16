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

	numPools  = 0x04
	size_pool = 0x04
)

type objectPool[T any] struct { // for now bad pointers with uintptr and generics
	// im still thinking about that....
	_          noCopy
	obj        [][]T
	freeptr    []uintptr
	allocate   func() T
	currOffset int
	currChunk  int
	chunkSize  int
	cap        int
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
	p.obj = append(p.obj, make([]T, p.chunkSize))
}

func newObjPool[T any](cap, chunkSize int, f func() T) *objectPool[T] {
	pool := &objectPool[T]{allocate: f}
	if cap <= 0 || cap > MAX_SIZE {
		cap = MAX_SIZE
	}
	pool.chunkSize = chunkSize
	pool.cap = cap

	if cap == 0 {
		pool.obj = make([][]T, 0, KB)
		pool.freeptr = make([]uintptr, 0, KB)
	} else {
		pool.obj = make([][]T, 0, pool.chunkSize)
		pool.freeptr = make([]uintptr, 0, pool.cap)
	}
	return pool
}

func (p *objectPool[T]) get() T {
	// if has free slots
	if len(p.freeptr) != 0 {
		ptr := p.freeptr[len(p.freeptr)-1]
		p.freeptr = p.freeptr[:len(p.freeptr)-1]
		return *p._t_(ptr)
	}

	// create object with function
	obj := p.allocate()

	// if currentchunk is full allocate new
	if len(p.obj) == 0 || p.currOffset == len(p.obj[p.currChunk]) {
		p.malloc()
		p.currOffset = 0
		if len(p.obj) > 1 {
			p.currChunk++
		}
	}

	// save object in current chunk
	p.obj[p.currChunk][p.currOffset] = obj
	p.currOffset++

	return obj
}

func (o *objectPool[T]) put(obj T) {
	if len(o.obj) >= o.cap {
		return
	}

	o.freeptr = append(o.freeptr, o._u_(&obj))
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
