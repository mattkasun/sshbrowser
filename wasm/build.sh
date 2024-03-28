#!/bin/bash
GOOS=js GOARCH=wasm go build -o ../server/html/main.wasm .