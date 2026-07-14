# Buf tooling expects a fully qualified path to the plugins directory.
BUF_PLUGINS_DIR ?= $(shell pwd)/.buf-plugins
BUF=go run github.com/bufbuild/buf/cmd/buf@v1.50.0

.PHONY: ensure-buf-plugins-dir
ensure-buf-plugins-dir:
	mkdir -p $(BUF_PLUGINS_DIR)

.PHONY: install-buf-plugins
install-buf-plugins: ensure-buf-plugins-dir ## Installs protoc plugins required by our buf config.
	GOBIN=$(BUF_PLUGINS_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5

.PHONY: generate-code
generate-code: install-buf-plugins ## Rebuild generated code
	PATH=$(BUF_PLUGINS_DIR):$$PATH $(BUF) generate --template buf.gen.yaml --debug https://github.com/biscuit-auth/biscuit.git#ref=v3.3
	go generate ./...
