package auth

type JWTDriver struct {
}

func NewJWTDriver(config interface{}) interface{} {
	if _, ok := config.(*JWTConfig); !ok {
		panic("jwt driver config must be a pointer of JWTConfig type")
	}

	return &JWTDriver{}
}
