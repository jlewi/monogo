ROOT := $(shell git rev-parse --show-toplevel)
echo:
	echo ROOT=$(ROOT)

build-dir:
	mkdir -p .build

build-go: build-dir
	CGO_ENABLED=0 go build -o .build/devcli github.com/jlewi/monogo/cli

tidy-go:
	gofmt -s -w .
	goimports -w .

lint-go:
	# golangci-lint automatically searches up the root tree for configuration files.
	golangci-lint run

test-go:
	go test -v ./...

test-go-integration:
	go test --tags=integration -v ./...