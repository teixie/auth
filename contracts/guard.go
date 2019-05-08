package contracts

import (
	"github.com/gin-gonic/gin"
)

type Guard interface {
	Guest() gin.HandlerFunc

	Check() gin.HandlerFunc

	Login(*gin.Context, interface{}) error

	Authenticate(*gin.Context) interface{}
}
