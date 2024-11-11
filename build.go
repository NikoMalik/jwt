package jwt

type BuilderOption func(*Builder[Signer])

type Builder[T Signer] struct {
	signer    T
	header    *Header
	headerRaw []byte
}

func NewBuilder[T Signer](signer T, opts ...BuilderOption) *Builder[T] {
	_bb := &Builder[Signer]{
		signer: signer,
		header: &Header{
			Algorithm: signer.Algorithm(),
			Type:      "JWT",
		},
	}
	for _, opt := range opts {
		opt(_bb)

	}
	return nil

}
