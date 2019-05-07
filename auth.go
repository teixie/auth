package auth

import (
	"github.com/gin-gonic/gin"
)

const (
	JWTGuard = "jwt"
)

type guard struct {
	name   string
	driver interface{}
}

func (g guard) Guest() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func (g guard) Check() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

var (
	guards  = make(map[string]*guard)
	drivers = map[string]func(interface{}) interface{}{
		JWTGuard: NewJWTDriver,
	}
)

// Register guard.
func RegisterGuard(name string, driver string, config interface{}) {
	if _, ok := drivers[driver]; ok {
		guards[name] = &guard{
			name:   name,
			driver: drivers[driver](config),
		}
		return
	}

	panic("driver not found")
}

// Get guard by name.
func Guard(name string) *guard {
	if _, ok := guards[name]; ok {
		return guards[name]
	}

	panic("guard not found")
}
