package contracts

import (
	"github.com/gin-gonic/gin"
)

type Driver interface {
	Authenticate(*gin.Context) interface{}
}
