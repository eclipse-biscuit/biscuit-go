IMAGE ?= biscuit-go-test

.PHONY: all build test test-local verify clean

all: verify test

build:
	go build ./...

# Tests run inside a container so that results do not depend on the host
# toolchain; the Go version is pinned in test.Dockerfile. Use `make test-local`
# to run them directly on the host.
test:
	docker build --file test.Dockerfile --tag $(IMAGE) .
	docker run --rm $(IMAGE)

test-local:
	./script/test.sh

verify:
	./script/verify.sh

clean:
	rm -rf build
