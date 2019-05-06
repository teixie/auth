package jwtguard

type guard struct {

}

func New() (*guard, error) {
	return &guard{}, nil
}
