ROOT := $(shell git rev-parse --show-toplevel)
echo:
	echo ROOT=$(ROOT)

build-dir:
	mkdir -p .build

build: build-dir
	CGO_ENABLED=0 go build -o .build/devcli github.com/jlewi/monogo/cli

tidy:
	gofmt -s -w .
	goimports -w .

lint:
	# golangci-lint automatically searches up the root tree for configuration files.
	golangci-lint run

# Run the unittests. We set GITHUB_ACTIONS=true to disable
# tests that don't run in GHA
test:
	GITHUB_ACTIONS=true go test -v ./...

test-go-integration:
	go test --tags=integration -v ./...