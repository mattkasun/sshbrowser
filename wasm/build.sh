#!/bin/bash
GOOS=js GOARCH=wasm go build -o ../html/main.wasm .
gzip ../html/main.wasm
