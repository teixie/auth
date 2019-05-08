package auth

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/teixie/auth/contracts"
	"github.com/teixie/hawking"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// ErrEmptyUserResolver can be thrown if user resolver is empty
	ErrEmptyUserResolver = errors.New("user resolver is empty")

	// ErrEmptyUser can be thrown if user is empty
	ErrEmptyUser = errors.New("user is empty")

	// ErrFailedCreateToken can be thrown if token create failed
	ErrFailedCreateToken = errors.New("create token failed")

	// Default tokenLookup
	defaultTokenLookup = "header:Authorization"

	// Default tokenHeadName
	defaultTokenHeadName = "Bearer"

	// Default signingAlgorithm
	defaultSigningAlgorithm = "HS256"
)

type jwtGuard struct {
	name             string
	key              []byte
	signingAlgorithm string
	timeout          time.Duration
	tokenLookup      string
	tokenHeadName    string
	privKeyFile      string
	pubKeyFile       string
	privKey          *rsa.PrivateKey
	pubKey           *rsa.PublicKey
	userResolver     func(string) contracts.User
}

func (j *jwtGuard) readKeys() error {
	err := j.privateKey()
	if err != nil {
		return err
	}
	err = j.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (j *jwtGuard) privateKey() error {
	keyData, err := ioutil.ReadFile(j.privKeyFile)
	if err != nil {
		return ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	j.privKey = key
	return nil
}

func (j *jwtGuard) publicKey() error {
	keyData, err := ioutil.ReadFile(j.pubKeyFile)
	if err != nil {
		return ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	j.pubKey = key
	return nil
}

func (j *jwtGuard) usingPublicKeyAlgo() bool {
	switch j.signingAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

func (j *jwtGuard) Init() error {
	if j.tokenLookup == "" {
		j.tokenLookup = defaultTokenLookup
	}

	if j.signingAlgorithm == "" {
		j.signingAlgorithm = defaultSigningAlgorithm
	}

	j.tokenHeadName = strings.TrimSpace(j.tokenHeadName)
	if len(j.tokenHeadName) == 0 {
		j.tokenHeadName = defaultTokenHeadName
	}

	if j.usingPublicKeyAlgo() {
		return j.readKeys()
	}

	return nil
}

func (j *jwtGuard) getTokenFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == j.tokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (j *jwtGuard) getTokenFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (j *jwtGuard) getTokenFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (j *jwtGuard) getTokenFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (j *jwtGuard) getToken(c *gin.Context) (string, error) {
	var token string
	var err error

	methods := strings.Split(j.tokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = j.getTokenFromHeader(c, v)
		case "query":
			token, err = j.getTokenFromQuery(c, v)
		case "cookie":
			token, err = j.getTokenFromCookie(c, v)
		case "param":
			token, err = j.getTokenFromParam(c, v)
		}
	}

	c.Set(j.name+":TOKEN", token)

	return token, err
}

// Parse jwt token from gin context
func (j *jwtGuard) parseToken(c *gin.Context) (*jwt.Token, error) {
	token, err := j.getToken(c)
	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(j.signingAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}

		if j.usingPublicKeyAlgo() {
			return j.pubKey, nil
		}

		return j.key, nil
	})
}

// GetClaimsFromJWT get claims from JWT token
func (j *jwtGuard) getClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	token, err := j.parseToken(c)
	if err != nil {
		return nil, err
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

func (j *jwtGuard) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if j.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(j.privKey)
	} else {
		tokenString, err = token.SignedString(j.key)
	}
	return tokenString, err
}

// createToken method that clients can use to get a jwt token.
func (j *jwtGuard) createToken(user contracts.User) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(j.signingAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	expire := hawking.Now().Add(j.timeout)
	claims["id"] = user.GetIdString()
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = hawking.Now().Unix()
	tokenString, err := j.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire.Time(), nil
}

func (j *jwtGuard) user(c *gin.Context) contracts.User {
	if user, exists := c.Get(j.name); exists {
		if usr, ok := user.(contracts.User); ok {
			return usr
		}
		return nil
	}

	user := j.Authenticate(c)
	c.Set(j.name, user)

	return user
}

func (j *jwtGuard) Authenticate(c *gin.Context) contracts.User {
	claims, err := j.getClaimsFromJWT(c)
	if err != nil {
		return nil
	}

	if claims["id"] == nil {
		return nil
	}

	if _, ok := claims["id"].(string); !ok {
		return nil
	}

	if claims["exp"] == nil {
		return nil
	}

	if _, ok := claims["exp"].(float64); !ok {
		return nil
	}

	if int64(claims["exp"].(float64)) < hawking.Now().Unix() {
		return nil
	}

	c.Set(j.name+":PAYLOAD", claims)

	return j.userResolver(claims["id"].(string))
}

func (j *jwtGuard) Login(c *gin.Context, user contracts.User) error {
	if user == nil {
		return ErrEmptyUser
	}

	token, expire, err := j.createToken(user)
	if err != nil {
		return ErrFailedCreateToken
	}

	c.Set(j.name, user)
	c.Set(j.name+":TOKEN", token)
	c.Set(j.name+":TOKEN_EXPIRE", expire)

	return nil
}

func (j *jwtGuard) Guest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if j.user(c) != nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"code": http.StatusConflict,
				"msg":  "Authorized",
				"data": nil,
			})
		}

		c.Next()
	}
}

func (j *jwtGuard) Check() gin.HandlerFunc {
	return func(c *gin.Context) {
		if j.user(c) == nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"code": http.StatusUnauthorized,
				"msg":  "Unauthorized",
				"data": nil,
			})
		}

		c.Next()
	}
}

func NewJWTGuard(name string, config interface{}) *jwtGuard {
	if cfg, ok := config.(*JWTConfig); ok {
		if err := cfg.Validate(); err != nil {
			panic(err.Error())
		}

		g := &jwtGuard{
			name:             name,
			key:              cfg.Key,
			signingAlgorithm: cfg.SigningAlgorithm,
			timeout:          cfg.Timeout,
			tokenLookup:      cfg.TokenLookup,
			tokenHeadName:    cfg.TokenHeadName,
			privKeyFile:      cfg.PrivKeyFile,
			pubKeyFile:       cfg.PubKeyFile,
			userResolver:     cfg.UserResolver,
		}
		if err := g.Init(); err != nil {
			panic(err.Error())
		}

		return g
	}

	panic("jwt guard config must be a pointer of JWTConfig type")
}
