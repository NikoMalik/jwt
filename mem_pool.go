package jwt

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
)

func alignSize(size, alignment int) int {
	if size%alignment == 0 {
		return size
	}
	return ((size / alignment) + 1) * alignment
}

type objectPool[T any] struct {
	_        noCopy
	obj      []T
	allocate func() T
	cap      int
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
		pool.obj = make([]T, 0, KB)
		// sht := (*reflect.SliceHeader)(unsafe.Pointer(&pool.obj))
		// sht.Cap = KB
		// sht.Len = 0
		// sht.Data = uintptr(unsafe.Pointer(&j))

	} else {
		pool.cap = cap
		pool.obj = make([]T, 0, alignSize(cap, B_8))
		// sht := (*reflect.SliceHeader)(unsafe.Pointer(&pool.obj))

	}

	return pool
}

func (o *objectPool[T]) get() T {

	if len(o.obj) > 0 {

		obj := o.obj[len(o.obj)-1]
		o.obj = o.obj[:len(o.obj)-1]
		return obj
	}
	return o.allocate() // Create a new object if pool is empty
}
func (o *objectPool[T]) put(obj T) {
	if len(o.obj) < o.cap {

		o.obj = append(o.obj, obj)
	}
	return

}

func (o *objectPool[T]) allocateMore() {
	newCap := alignSize(o.cap*2, B_8)
	if newCap > GB {
		newCap = GB
	}
	if newCap > o.cap {
		o.cap = newCap

		o.obj = append(o.obj, make([]T, 0, newCap-len(o.obj))...)
	}
}
func level(cap int) int {
	if cap <= 0 || cap > GB {
		return -1
	}
	if cap <= KB {
		return 1
	} else if cap <= KB_32 {
		return 2
	} else if cap <= MB {
		return 3
	} else if cap <= MB_32 {
		return 4
	} else if cap <= GB {
		return 5
	}
	return -1
}

// func i[T any]() *multiPool[T] {
//
//		var buckets [1]*multiPool[T]
//		buckets[0] = newMultiPool[T](KB, 0, B_8, nil)
//		// buckets[1] = newMultiPool[any](KB_32, KB, B_256, nil)
//		// buckets[2] = newMultiPool[any](MB, KB_32, KB_8, nil)
//		// buckets[3] = newMultiPool[any](MB_32, MB, KB_256, nil)
//		// buckets[4] = newMultiPool[any](GB, MB_32, MB_8, nil)
//	    return buckets[0]
//
// }
func setFactoryFunc[T any](pool *objectPool[T], f func() T) {
	if pool != nil {
		pool.allocate = f
	}
}
