package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/teixie/auth/contracts"
)

const (
	JWTGuard = "jwt"
)

var (
	guards  = make(map[string]*guard)
	drivers = map[string]func(string, interface{}) interface{}{
		JWTGuard: newJWTDriver,
	}
)

type guard struct {
	name   string
	driver interface{}
}

func (g guard) Guest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if g.user(c) != nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"code": http.StatusConflict,
				"msg":  "Authorized",
				"data": nil,
			})
		}

		c.Next()
	}
}

func (g guard) Check() gin.HandlerFunc {
	return func(c *gin.Context) {
		if g.user(c) == nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"code": http.StatusUnauthorized,
				"msg":  "Unauthorized",
				"data": nil,
			})
		}

		c.Next()
	}
}

func (g guard) Login(c *gin.Context, user interface{}) error {
	return g.driver.(contracts.Driver).Login(c, user)
}

func (g guard) user(c *gin.Context) interface{} {
	if user, exists := c.Get(g.name); exists {
		return user
	}

	user := g.driver.(contracts.Driver).Authenticate(c)
	c.Set(g.name, user)

	return user
}

// Register guard.
func RegisterGuard(name string, driver string, config interface{}) {
	if handler, ok := drivers[driver]; ok {
		guards[name] = &guard{
			name:   name,
			driver: handler(name, config),
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
