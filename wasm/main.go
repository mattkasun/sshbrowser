//go:build js && wasm

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"syscall/js"

	"golang.org/x/crypto/ssh"
)

// Login contains login information.
type Login struct {
	Message string        `json:"message"`
	Sig     ssh.Signature `json:"sig"`
	User    string        `json:"user"`
}

var key []byte

func main() {
	c := make(chan struct{})
	// fileInput.Set("oninput", js.FuncOf(fileSelect))
	println("WASM go initialized")
	registerCallBacks()
	<-c
}

func fileSelect(this js.Value, p []js.Value) any {
	fileInput := js.Global().Get("document").Call("getElementById", "file")
	fileInput.Get("files").Index(0).Call("arrayBuffer").Call("then", js.FuncOf(func(this js.Value, p []js.Value) any {
		data := js.Global().Get("Uint8Array").New(p[0])
		dst := make([]byte, data.Get("byteLength").Int())
		js.CopyBytesToGo(dst, data)
		key = dst
		return nil
	}))
	// Call("then", js.FuncOf(getKey))
	return nil
}

func registerCallBacks() {
	js.Global().Set("validate", js.FuncOf(validate))
	js.Global().Set("fileSelect", js.FuncOf(fileSelect))
}

func validate(this js.Value, p []js.Value) any {
	var signer ssh.Signer
	var err error
	var passphraseErr *ssh.PassphraseMissingError
	username := js.Global().Get("document").Call("getElementById", "username").Get("value").String()
	passphrase := js.Global().Get("document").Call("getElementById", "passphrase").Get("value").String()
	if _, err := mail.ParseAddress(username); err != nil {
		js.Global().Get("alert").Invoke("invalid email in username: " + err.Error())
		return nil
	}
	fileSelect(this, p)
	if passphrase == "" {
		signer, err = ssh.ParsePrivateKey(key)
		if err != nil {
			if errors.As(err, &passphraseErr) {
				js.Global().Get("alert").Invoke("passphrase is required")
			} else {
				js.Global().Get("alert").Invoke("Invalid Key")
			}
			return nil
		}
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		if err != nil {
			js.Global().Get("alert").Invoke("Invalid Key or Passphrase")
			return nil
		}
	}
	processLogin(username, signer)
	return nil
}

func processLogin(username string, signer ssh.Signer) {
	random := make(chan []byte)
	go func() {
		resp, err := http.Get("hello")
		if err != nil {
			js.Global().Get("alert").Invoke("error: " + err.Error())
			close(random)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			js.Global().Get("alert").Invoke("error: " + err.Error())
			close(random)
			return
		}
		random <- body
	}()
	go func() {
		data := <-random
		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			js.Global().Get("alert").Invoke("error signing message: " + err.Error())
			return
		}
		login := Login{
			Message: string(data),
			Sig:     *sig,
			User:    username,
		}
		payload, err := json.Marshal(login)
		if err != nil {
			js.Global().Get("alert").Invoke("marshal error: " + err.Error())
			return
		}
		resp, err := http.Post("/login", "application/json", bytes.NewBuffer(payload))
		if err != nil {
			js.Global().Get("alert").Invoke("http error: " + err.Error())
			return
		}
		if resp.StatusCode != http.StatusOK {
			js.Global().Get("alert").Invoke("http error: " + resp.Status)
			return
		}
		js.Global().Get("location").Set("href", "/")
	}()
}
