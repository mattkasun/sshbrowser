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
	"time"

	"github.com/mattkasun/sshbrowser"
	"golang.org/x/crypto/ssh"
)

var (
	fileInput  js.Value
	fileName   js.Value
	userName   js.Value
	passphrase js.Value
	key        []byte
	signer     ssh.Signer
)

func main() {
	document := js.Global().Get("document")
	fileInput = document.Call("getElementById", "file")
	userName = document.Call("getElementById", "username")
	passphrase = document.Call("getElementById", "passphrase")
	fileInput.Set("oninput", js.FuncOf(fileSelect))
	login := document.Call("getElementById", "button")
	login.Set("onclick", js.FuncOf(processLogin))
	select {}
}

func processLogin(this js.Value, p []js.Value) interface{} {
	username := userName.Get("value").String()
	passphrase := js.Global().Get("document").Call("getElementById", "passphrase").Get("value").String()
	message, err := revalidate(username, passphrase)
	if err != nil {
		js.Global().Get("alert").Invoke(message + err.Error())
		return nil
	}
	random := make(chan []byte)
	go func() {
		resp, err := http.Get("/hello")
		if err != nil {
			js.Global().Get("alert").Invoke("Error: " + err.Error())
			close(random)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			js.Global().Get("alert").Invoke("Error: " + err.Error())
			close(random)
			return
		}
		random <- body
	}()
	go func() {
		data := <-random
		client := http.Client{Timeout: time.Second}
		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			js.Global().Get("alert").Invoke("Error sigining message " + err.Error())
			return
		}
		login := sshbrowser.Login{
			Message: string(data),
			Sig:     *sig,
			User:    username,
		}
		payload, err := json.Marshal(login)
		if err != nil {
			js.Global().Get("alert").Invoke("marshal error " + err.Error())
			return
		}
		request, err := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(payload))
		if err != nil {
			js.Global().Get("alert").Invoke("http error " + err.Error())
			return
		}
		resp, err := client.Do(request)
		if err != nil {
			js.Global().Get("alert").Invoke("http error " + err.Error())
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			js.Global().Get("alert").Invoke("http error " + err.Error())
			return
		}
		if resp.StatusCode != http.StatusOK {
			js.Global().Get("alert").Invoke("http error " + resp.Status + " " + string(body))
			return
		}
		js.Global().Get("alert").Invoke("login successful")
		redirect()
	}()

	return nil
}

func fileSelect(this js.Value, p []js.Value) interface{} {
	fileInput.Get("files").Index(0).Call("arrayBuffer").Call("then", js.FuncOf(validate))
	return nil
}

func revalidate(username, passphrase string) (string, error) {
	if _, err := mail.ParseAddress(username); err != nil {
		return "Invalid email", err
	}
	if passphrase == "" {
		if _, err := ssh.ParsePrivateKey(key); err != nil {
			return "Invalid key", err
		}
	} else {
		if _, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase)); err != nil {
			return "Invalid key or passphrase", err
		}
	}
	return "Valid", nil
}

func validate(this js.Value, p []js.Value) interface{} {
	var passphraseErr *ssh.PassphraseMissingError
	var err error
	phrase := ""
	data := js.Global().Get("Uint8Array").New(p[0])
	dst := make([]byte, data.Get("byteLength").Int())
	js.CopyBytesToGo(dst, data)
	key = dst
	signer, err = ssh.ParsePrivateKey(dst)
	if err != nil {
		if errors.As(err, &passphraseErr) {
			phrase = js.Global().Get("prompt").Invoke("Enter passphrase").String()
			js.Global().Get("document").Call("getElementById", "passphrase").Set("value", phrase)
			signer, err = ssh.ParsePrivateKeyWithPassphrase(dst, []byte(phrase))
			if err != nil {
				js.Global().Get("alert").Invoke("Invalid passphrase")
			}
		} else {
			js.Global().Get("alert").Invoke("Invalid key")
		}
	} else {
		passphrase.Set("value", "")
	}
	return nil
}

func redirect() {
	js.Global().Get("location").Set("href", "/")
}
