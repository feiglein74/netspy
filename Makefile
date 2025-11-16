.PHONY: help build test lint fmt vet clean coverage run install

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=netspy
BINARY_UNIX=$(BINARY_NAME)
BINARY_WIN=$(BINARY_NAME).exe
GO=go
GOLANGCI_LINT=golangci-lint

## help: Show this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## build: Build the binary
build:
	@echo "Building..."
	$(GO) build -o $(BINARY_WIN) .
	@echo "Build complete: $(BINARY_WIN)"

## build-all: Build for all platforms
build-all:
	@echo "Building for all platforms..."
	GOOS=darwin GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build -o dist/$(BINARY_NAME)-darwin-arm64 .
	GOOS=linux GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-linux-amd64 .
	GOOS=windows GOARCH=amd64 $(GO) build -o dist/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Multi-platform build complete!"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

## test-short: Run tests without verbose output
test-short:
	@echo "Running tests (short)..."
	$(GO) test ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## coverage: Show coverage in terminal
coverage:
	@echo "Running tests with coverage..."
	$(GO) test -cover ./...

## lint: Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	$(GOLANGCI_LINT) run ./...

## lint-fix: Run golangci-lint with auto-fix
lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	$(GOLANGCI_LINT) run --fix ./...

## fmt: Format all Go code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "Code formatted!"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME) $(BINARY_WIN)
	rm -rf dist/
	rm -f coverage.out coverage.html
	$(GO) clean
	@echo "Clean complete!"

## run: Build and run the binary
run: build
	./$(BINARY_WIN)

## install: Install the binary to GOPATH/bin
install:
	@echo "Installing..."
	$(GO) install .
	@echo "Installation complete!"

## check: Run all quality checks (fmt, vet, lint, test)
check: fmt vet lint test-short
	@echo "All checks passed!"

## qa: Full quality assurance (check + coverage)
qa: check test-coverage
	@echo "QA complete!"
