package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/devilcove/cookie"
	"golang.org/x/crypto/ssh"
)

const (
	cookieName = "sshbrower"
	cookieAge  = 300
	stringLen  = 14
)

var templates *template.Template

func setupRouter() http.Handler {
	templates = template.Must(template.ParseGlob("html/*.html"))
	router := http.NewServeMux()
	staticPages(router)
	plainPages(router)
	restricted := restrictedPages()
	router.Handle("/page/", http.StripPrefix("/page", auth(restricted)))
	router.HandleFunc("GET /{$}", mainPage)
	return Logger(router)
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	_, err := cookie.Get(r, cookieName)
	if err != nil {
		render(w, "welcome", nil)
		return
	}
	page := Page{}
	for i := range 5 {
		i++
		if i == 1 {
			continue
		}
		page.Links = append(page.Links, strconv.Itoa(i))
	}
	page.Page = "1"
	render(w, "main", page)
}

func staticPages(router *http.ServeMux) {
	router.HandleFunc("GET /styles.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/styles.css")
	})
	router.HandleFunc("GET /wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/wasm_exec.js")
	})
	router.HandleFunc("GET /main.wasm", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/main.wasm")
	})
	router.HandleFunc("GET /bmc-button.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/bmc-button.svg")
	})
	router.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/ssh.svg")
	})
}

func plainPages(router *http.ServeMux) {
	router.HandleFunc("GET /hello", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, randomString(stringLen))
	})
	router.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		render(w, "login", nil)
	})
	router.HandleFunc("POST /login", login)
	router.HandleFunc("GET /register", func(w http.ResponseWriter, _ *http.Request) {
		render(w, "register", nil)
	})
	router.HandleFunc("POST /register", register)
	router.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		cookie.Clear(w, cookieName, false)
		render(w, "welcome", nil)
	})
}

func restrictedPages() *http.ServeMux {
	restricted := http.NewServeMux()

	restricted.HandleFunc("GET /ip", func(w http.ResponseWriter, r *http.Request) {
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remote = r.RemoteAddr
		}
		if x := r.Header.Get("X-Forwared-For"); x != "" {
			remote = x
		}
		render(w, "myIP", remote)
	})
	restricted.HandleFunc("GET /{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		page := Page{Page: id}
		for i := range 5 {
			i++
			if id == strconv.Itoa(i) {
				continue
			}
			page.Links = append(page.Links, strconv.Itoa(i))
		}
		render(w, "main", page)
	})
	return restricted
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func render(w io.Writer, template string, data any) {
	if err := templates.ExecuteTemplate(w, template, data); err != nil {
		slog.Error("render template", "caller", caller(2), "name", template,
			"data", data, "error", err)
	}
}

func caller(depth int) string {
	pc, file, no, ok := runtime.Caller(depth)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return fmt.Sprintf("%s %s:%d", details.Name(), filepath.Base(file), no)
	}
	return "unknown caller"
}

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := cookie.Get(r, cookieName); err != nil {
			processError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var login Login
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		processError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := json.Unmarshal(body, &login); err != nil {
		processError(w, http.StatusBadRequest, "unmarshal body: "+err.Error())
		return
	}
	pub, ok := users[login.User]
	if !ok {
		processError(w, http.StatusBadRequest, "no such user")
		return
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		processError(w, http.StatusBadRequest, "parse public key: "+err.Error())
		return
	}
	if err := pubKey.Verify([]byte(login.Message), &login.Sig); err != nil {
		processError(w, http.StatusBadRequest, "unable to verify key: "+err.Error())
		return
	}
	cookie.Save(w, cookieName, []byte("ssh browser cookie"))
	io.WriteString(w, "ok")
}

func register(w http.ResponseWriter, r *http.Request) {
	reg := Registration{
		User: r.FormValue("user"),
		Key:  r.FormValue("key"),
	}
	if reg.Key == "" {
		processError(w, http.StatusBadRequest, "empty key")
		return
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(reg.Key)); err != nil {
		processError(w, http.StatusBadRequest, "parse key: "+err.Error())
		return
	}
	_, ok := users[reg.User]
	if ok {
		processError(w, http.StatusBadRequest, "user exists")
		return
	}
	users[reg.User] = []byte(reg.Key)
	slog.Info("user registration", "user", reg.User)
	render(w, "login", nil)
}

func processError(w http.ResponseWriter, code int, message string) {
	slog.Error("process error", "caller", caller(2), "message", message)
	w.WriteHeader(code)
	render(w, "error", message)
}
