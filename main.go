/*
Copyright © 2023 Matthew R Kasun <mkasun@nusak.ca>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devilcove/cookie"
)

var users = map[string][]byte{}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	slog.SetDefault(slog.Default())
	if err := cookie.New(cookieName, cookieAge); err != nil {
		slog.Error("set cookier", "error", err)
		return
	}
	server := http.Server{
		Addr:              ":8080",
		Handler:           setupRouter(),
		ReadHeaderTimeout: time.Second,
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		if err := server.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server", "error", err)
		}
	}()
	slog.Info("server started on port :8080")
	<-quit
	if err := server.Shutdown(context.Background()); err != nil {
		slog.Error("server shutdown", "error", err)
	}
}
