package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/teixie/auth/contracts"
)

const (
	JWTGuard = "jwt"
)

var (
	guards  = make(map[string]*guard)
	drivers = map[string]func(interface{}) interface{}{
		JWTGuard: func(config interface{}) interface{} {
			return NewJWTGuard(config)
		},
	}
)

type guard struct {
	name   string
	driver contracts.Guard
}

func (g guard) Guest() gin.HandlerFunc {
	return g.driver.Guest()
}

func (g guard) Check() gin.HandlerFunc {
	return g.driver.Check()
}

func (g guard) Login(c *gin.Context, user contracts.User) error {
	return g.driver.Login(c, user)
}

// Register guard.
func RegisterGuard(name string, driver string, config interface{}) {
	if name == "" {
		panic("guard name is empty")
	}

	if handler, ok := drivers[driver]; ok {
		obj := handler(config)
		if dri, ok := obj.(contracts.Guard); ok {
			guards[name] = &guard{
				name:   name,
				driver: dri,
			}
			return
		}

		panic("guard is invalid")
	}

	panic("driver not found")
}

// Get guard by name.
func Guard(name string) *guard {
	if g, ok := guards[name]; ok {
		return g
	}

	panic("guard not found")
}
