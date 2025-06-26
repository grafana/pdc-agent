BINARY_NAME=pdc

all: lint build test

build:
	go build -tags="$(shell cat .go-build-tags)" -ldflags="-s -w" -o ${BINARY_NAME} ./cmd/pdc/

test:
	GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-Wno-error" go test -tags="$(shell cat .go-build-tags)" -timeout=5m -race -coverprofile=c.out ./...

lint:
	golangci-lint run --max-same-issues=0 --max-issues-per-linter=0

clean:
	go clean
	rm ${BINARY_NAME}

.PHONY: all build test lint clean
