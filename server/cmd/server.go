package cmd

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/kr/pretty"
	"github.com/mattkasun/sshbrowser"
	"golang.org/x/crypto/ssh"
)

var users map[string]string

func run(p int) {
	users = make(map[string]string)
	router := setupRouter()
	router.Run(fmt.Sprintf("127.0.0.1:%d", p))
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.LoadHTMLGlob("html/*.html")
	store := cookie.NewStore([]byte(randomString(32)), []byte(randomString(32)))
	store.Options(sessions.Options{MaxAge: 300, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	session := sessions.Sessions("sshlogin", store)
	r.Use(session)
	r.StaticFile("/wasm_exec.js", "./html/wasm_exec.js")
	r.StaticFile("/main.wasm", "./html/main.wasm")
	r.StaticFile("/main.wasm.gz", "./html/main.wasm.gz")
	r.StaticFile("/bmc-button.svg", "./html/bmc-button.svg")
	r.GET("", auth, func(c *gin.Context) {
		page := sshbrowser.Page{}
		for i := range 5 {
			i++
			if i == 1 {
				continue
			}
			page.Links = append(page.Links, strconv.Itoa(i))
		}
		page.Page = "1"
		c.HTML(http.StatusOK, "main", page)
	})
	r.GET("/hello", func(c *gin.Context) {
		c.String(200, randomString(14))
	})
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login", nil)
	})
	r.POST("/login", func(c *gin.Context) {
		var login sshbrowser.Login
		if err := c.ShouldBindJSON(&login); err != nil {
			log.Println("login ", err)
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		fmt.Println(users)
		pub, ok := users[login.User]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := pubKey.Verify([]byte(login.Message), &login.Sig); err != nil {
			log.Println("login verify ", err)
			c.JSON(401, gin.H{"error": err.Error()})
			return
		}
		session := sessions.Default(c)
		session.Set("loggedIn", true)
		session.Set("user", login.User)
		session.Save()
		c.JSON(200, gin.H{"message": "Hello World"})
	})
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register", nil)
	})
	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.HTML(http.StatusOK, "login", nil)
	})
	r.POST("/register", func(c *gin.Context) {
		var reg sshbrowser.Registation
		reg.User = c.PostForm("user")
		reg.Key = c.PostForm("key")
		//if err := c.Bind(&reg); err != nil {
		//	c.HTML(http.StatusBadRequest, "error", err.Error())
		//	return
		//}
		pretty.Println(reg)
		if reg.Key == "" {
			c.HTML(http.StatusBadRequest, "error", "public key cannot be empty")
			return
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(reg.Key)); err != nil {
			slog.Error(err.Error())
			c.HTML(http.StatusBadRequest, "error", "invalid ssh public key")
			return
		}
		_, ok := users[reg.User]
		if ok {
			c.HTML(http.StatusBadRequest, "error", "username is taken")
			return
		}
		users[reg.User] = reg.Key
		fmt.Println(users[reg.User])
		c.HTML(http.StatusOK, "login", nil)
	})
	restricted := r.Group("page/", auth)
	{
		restricted.GET("ip", func(c *gin.Context) {
			c.String(http.StatusOK, c.Request.RemoteAddr)
		})
		restricted.GET(":id", func(c *gin.Context) {
			id := c.Param("id")
			page := sshbrowser.Page{}
			page.Page = id
			for i := range 5 {
				i++
				if id == strconv.Itoa(i) {
					continue
				}
				page.Links = append(page.Links, strconv.Itoa(i))
			}
			c.HTML(http.StatusOK, "main", page)
		})
	}
	return r
}

func auth(c *gin.Context) {
	var empty interface{}
	session := sessions.Default(c)
	user := session.Get("user")
	if user == empty {
		c.HTML(http.StatusUnauthorized, "error", "access denied")
		c.Abort()
		return
	}
	if _, ok := users[user.(string)]; !ok {
		c.HTML(http.StatusUnauthorized, "error", "access denied")
		c.Abort()
		return
	}
	loggedIn := session.Get("loggedIn")
	if loggedIn != true {
		c.HTML(http.StatusUnauthorized, "error", "access denied")
		c.Abort()
		return
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("randomString", err)
	}
	return base32.StdEncoding.EncodeToString(b)[:n]
}
