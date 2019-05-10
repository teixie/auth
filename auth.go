package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/teixie/auth/contracts"
)

var (
	guards  = make(map[string]*guard)
	drivers = make(map[string]func(interface{}) contracts.Guard)
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

// Register driver.
func RegisterDriver(driverName string, driver func(interface{}) contracts.Guard) {
	drivers[driverName] = driver
}

// Register guard.
func RegisterGuard(name string, driverName string, config interface{}) {
	if name == "" {
		panic("guard name is empty")
	}

	if handler, ok := drivers[driverName]; ok {
		guards[name] = &guard{
			name:   name,
			driver: handler(config),
		}
		return
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
