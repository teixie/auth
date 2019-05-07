package auth

import (
	"github.com/gin-gonic/gin"
)

type jwtDriver struct {
	key              []byte
	signingAlgorithm string
	tokenLookup      string
}

func (jd jwtDriver) Authenticate(c *gin.Context) interface{} {
	return nil
}

func newJWTDriver(config interface{}) interface{} {
	if cfg, ok := config.(*JWTConfig); ok {
		if err := cfg.Validate(); err != nil {
			panic(err.Error())
		}

		return &jwtDriver{
			key:              cfg.Key,
			signingAlgorithm: cfg.SigningAlgorithm,
			tokenLookup:      cfg.TokenLookup,
		}
	}

	panic("jwt driver config must be a pointer of JWTConfig type")
}
