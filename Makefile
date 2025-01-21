BINARY_NAME=pdc

all: lint build test

build:
	go build -o ${BINARY_NAME} ./cmd/pdc/

test:
	go test -timeout=5m -race -coverprofile=c.out ./...

lint:
	golangci-lint run --max-same-issues=0 --max-issues-per-linter=0

clean:
	go clean
	rm ${BINARY_NAME}

.PHONY: all build test lint clean
