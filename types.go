package main

import "golang.org/x/crypto/ssh"

// Login contains login information.
type Login struct {
	Message string        `json:"message"`
	Sig     ssh.Signature `json:"sig"`
	User    string        `json:"user"`
}

// Registration contains information to register a new user.
type Registration struct {
	User string `json:"user"`
	Key  string `json:"key"`
}

// Page contains page information.
type Page struct {
	Page  string
	Links []string
}
