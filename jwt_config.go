package auth

import (
	"github.com/gin-gonic/gin"
	"time"

	"github.com/teixie/auth/contracts"
)

type JWTConfig struct {
	// Secret key used for signing. Required.
	Key []byte

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// Private key file for asymmetric algorithms
	PrivKeyFile string

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// User resolver
	UserResolver func(string) contracts.User

	// Redirect if authenticated
	RedirectIfAuthenticated func(*gin.Context)

	// Redirect if unauthenticated
	RedirectIfUnauthenticated func(*gin.Context)
}

func (j *JWTConfig) Validate() error {
	if j.Key == nil {
		return ErrMissingSecretKey
	}

	if j.UserResolver == nil {
		return ErrEmptyUserResolver
	}

	return nil
}
