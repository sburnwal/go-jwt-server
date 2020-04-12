package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/appleboy/gin-jwt-server/config"
	"github.com/appleboy/gin-jwt-server/input"
	"github.com/appleboy/gin-jwt-server/model"
	status "github.com/appleboy/gin-status-api"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	ExpireTime	time.Duration 	= time.Minute * 60 * 24 * 30
	Realm		string        	= "jwt auth"
	JwtIssuer	string 			= "MyCompany"
	JwtAudience string 			= "MyApp"
	PrivateKeyFile string 		= "privkey.pem"
	PublicKeyFile string		= "pubkey.pem"
	SvrKeyFile string 			= "svrkey.pem"
	SvrCertFile string			= "svrcert.pem"
)

var keyFuncError error = fmt.Errorf("error loading key")

var (
	verifyKey  *rsa.PublicKey
	signKey    *rsa.PrivateKey

	defaultKeyFunc	jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { 
		return verifyKey, nil
	}

	orm         *xorm.Engine
	currentUser model.User
)

func initKeys() {
	log.Println("Initialzing RSA Public and Private Keys")
	signBytes, err := ioutil.ReadFile(PrivateKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil { 
		log.Fatal(err)
	}

	verifyBytes, err := ioutil.ReadFile(PublicKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil { 
		log.Fatal(err)
	}
}

func AbortWithError(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+Realm)
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
	c.Abort()
}

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user model.User
		var token *jwt.Token
		var err error
		var tokenStr string
		
		tokenStr, err = request.OAuth2Extractor.ExtractToken(c.Request)
		log.Println("Got token from request", tokenStr)
		if token, err = request.ParseFromRequest(c.Request, request.OAuth2Extractor, defaultKeyFunc); err == nil {
			claims := token.Claims.(jwt.MapClaims)
			log.Println("Token for user", claims["sub"], "expires", claims["exp"])
		}

		if err != nil {
			AbortWithError(c, http.StatusUnauthorized, "Invaild User Token")
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		_, err = orm.Where("id = ?", claims["id"]).Get(&user)
		if err != nil {
			AbortWithError(c, http.StatusInternalServerError, "DB Query Error")
			return
		}

		currentUser = user
	}
}

func LoginHandler(c *gin.Context) {
	var form input.Login
	var user model.User

	if c.BindJSON(&form) != nil {
		AbortWithError(c, http.StatusBadRequest, "Missing usename or password")
		return
	}

	found, err := orm.Where("username = ?", form.Username).Get(&user)

	if err != nil {
		AbortWithError(c, http.StatusInternalServerError, "DB Query Error")
		return
	}

	if found == false || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(form.Password)) != nil {
		AbortWithError(c, http.StatusUnauthorized, "Incorrect Username / Password")
		return
	}

	expire := time.Now().Add(ExpireTime)
	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    JwtIssuer,
		IssuedAt: time.Now().Unix(),
		ExpiresAt: expire.Unix(),
		Audience: JwtAudience,
		Subject: user.Id, 
		Id: user.Id,
	} 

	//create the token
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	tokenString, err := token.SignedString(signKey)

	if err != nil {
		AbortWithError(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

func RegisterHandler(c *gin.Context) {
	var form input.Login
	var user model.User

	if c.BindJSON(&form) != nil {
		AbortWithError(c, http.StatusBadRequest, "Missing usename or password")
		return
	}

	has, err := orm.Where("username = ?", form.Username).Get(&user)

	if has {
		AbortWithError(c, http.StatusBadRequest, "Username already exists")
		return
	}

	userId, err := uuid.NewV4()
	if err != nil {
		AbortWithError(c, http.StatusInternalServerError, err.Error())
	}

	if digest, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost); err != nil {
		AbortWithError(c, http.StatusInternalServerError, err.Error())
		return
	} else {
		form.Password = string(digest)
	}

	_, err = orm.Insert(&model.User{
		Id:       userId.String(),
		Username: form.Username,
		Password: form.Password,
	})

	if err != nil {
		AbortWithError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    "200",
		"message": "ok",
	})
}

func RefreshHandler(c *gin.Context) {
	var  token *jwt.Token
	var err error
	if token, err = request.ParseFromRequest(c.Request, request.OAuth2Extractor, defaultKeyFunc); err == nil {
		claims := token.Claims.(jwt.MapClaims)
		fmt.Printf("Token for user %v expires %v", claims["user"], claims["exp"])
	}
	if err != nil {
		AbortWithError(c, http.StatusInternalServerError, "Error parsing JWT")
		return
	}

	expire := time.Now().Add(ExpireTime)

	existingClaims := token.Claims.(jwt.MapClaims)
	// Create the Claims
	claims := &jwt.StandardClaims{
		Issuer:    JwtIssuer,
		IssuedAt: time.Now().Unix(),
		ExpiresAt: expire.Unix(),
		Audience: JwtAudience,
		Subject: existingClaims["id"].(string), 
		Id: existingClaims["id"].(string),
	} 

	//create the token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(signKey)

	if err != nil {
		AbortWithError(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

func HelloHandler(c *gin.Context) {
	currentTime := time.Now()
	currentTime.Format(time.RFC3339)
	c.JSON(200, gin.H{
		"current_time": currentTime,
		"text":         "Hi " + currentUser.Username + ", You are login now.",
	})
}

func initDB() {
	configs, _ := config.ReadConfig("config.json")

	connectStr := &mysql.Config{
		User:   configs.DB_USERNAME,
		Passwd: configs.DB_PASSWORD,
		AllowNativePasswords: true,
		Net:    "tcp",
		Addr:   net.JoinHostPort(configs.DB_HOST, strconv.Itoa(configs.DB_PORT)),
		DBName: configs.DB_NAME,
		Params: map[string]string{
			"charset": "utf8",
		},
	}

	db, err := xorm.NewEngine("mysql", connectStr.FormatDSN())

	if err != nil {
		log.Panic("DB connection initialization failed", err)
	}

	orm = db

	session := orm.Where("username = 'test")
	if session != nil {
		log.Println("Error intitializing the database")
		return
	}
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	initKeys()

	// initial DB setting
	initDB()

	r.POST("/login", LoginHandler)
	r.POST("/register", RegisterHandler)

	auth := r.Group("/auth")
	auth.Use(Auth())
	{
		auth.GET("/hello", HelloHandler)
		auth.GET("/refresh_token", RefreshHandler)
	}

	api := r.Group("/api")
	api.Use(Auth())
	{
		api.GET("/status", status.GinHandler)
	}

	endless.ListenAndServeTLS(":"+port, SvrCertFile, SvrKeyFile, r)
}
