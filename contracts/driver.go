package contracts

import (
	"github.com/gin-gonic/gin"
)

type Driver interface {
	Login(*gin.Context, interface{}) error
	Authenticate(*gin.Context) interface{}
}
