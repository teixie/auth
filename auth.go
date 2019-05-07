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

var guards = make(map[string]*guard)

func RegisterGuard(name string, driver string, config interface{}) {
	guards[name] = &guard{
		name: name,
	}
}

func Guard(name string) *guard {
	if _, ok := guards[name]; ok {
		return guards[name]
	}

	panic("guard not found")
}
