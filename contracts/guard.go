package contracts

import (
	"github.com/gin-gonic/gin"
)

type Guard interface {
	Guest() gin.HandlerFunc

	Check() gin.HandlerFunc

	Login(*gin.Context, User) error

	User(*gin.Context) User
}
