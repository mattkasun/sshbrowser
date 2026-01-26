package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
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
	// unauthorized
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
		http.ServeFile(w, r, "html/main.wasm.gz")
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
		render(w, "login", nil)
	})
}

func restrictedPages() *http.ServeMux {
	restricted := http.NewServeMux()

	restricted.HandleFunc("GET /ip", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.RemoteAddr)
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
			slog.Error("get cookie", "error", err)
			render(w, "error", "unauthorized")
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
		slog.Error("read body", "error", err)
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &login); err != nil {
		slog.Error("unmarshal body", "error", err)
		http.Error(w, "unmarshal body", http.StatusBadRequest)
		return
	}
	pub, ok := users[login.User]
	if !ok {
		slog.Error("user not found", "user", login.User)
		http.Error(w, "no such user", http.StatusBadRequest)
		return
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		slog.Error("parse key", "error", err)
		http.Error(w, "error parsing public key", http.StatusInternalServerError)
		return
	}
	if err := pubKey.Verify([]byte(login.Message), &login.Sig); err != nil {
		slog.Error("verify", "error", err)
		http.Error(w, "unable to verify key", http.StatusBadRequest)
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
		slog.Error("register", "error", "empty key")
		http.Error(w, "empty key", http.StatusBadRequest)
		return
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(reg.Key)); err != nil {
		slog.Error("parse key", "error", err)
		http.Error(w, "invalid ssh key", http.StatusBadRequest)
		return
	}
	_, ok := users[reg.User]
	if ok {
		slog.Error("registration", "error", "user exists")
		http.Error(w, "user exists", http.StatusBadRequest)
		return
	}
	users[reg.User] = []byte(reg.Key)
	slog.Info("user registration", "user", reg.User)
	render(w, "login", nil)
}
