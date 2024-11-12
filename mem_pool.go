package jwt

const (
	KB = 1 << 10
	MB = 1 << 20
	GB = 1 << 30
)

type objectPool[T any] struct {
	_   noCopy
	obj []T
	max int
	fu  func() T
}

func newObjPool[T any](max int, f func() T) *objectPool[T] {
	pool := &objectPool[T]{
		fu: f,
	}
	if max <= 1 {
		pool.max = 0x0FFFFFFF
		pool.obj = make([]T, 0, KB)
	} else {
		pool.max = max
		pool.obj = make([]T, 0, max)
	}

	return pool
}

func (o *objectPool[T]) get() T {

	if len(o.obj) == 0 {
		return o.fu()
	}
	obj := o.obj[len(o.obj)-1]
	o.obj = o.obj[:len(o.obj)-1]
	return obj
}

func (o *objectPool[T]) put(obj T) {
	if len(o.obj) >= o.max {
		return
	}
	o.obj = append(o.obj, obj)
}
