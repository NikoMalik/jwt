package jwt

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
