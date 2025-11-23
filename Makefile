# Makefile for go-fileencrypt

.PHONY: test security coverage tidy validate-all lint examples benchmark

test:
	go test ./... -v -race

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

lint:
	go vet ./...
	go fmt ./...
	@command -v staticcheck >/dev/null 2>&1 || (echo "Installing staticcheck..." && go install honnef.co/go/tools/cmd/staticcheck@latest)
	staticcheck ./...

security:
	@command -v gosec >/dev/null 2>&1 || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	@command -v govulncheck >/dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@echo "Running gosec..."
	gosec -fmt=json -out=gosec-report.json ./...
	@echo "Running govulncheck..."
	govulncheck ./...

examples:
	@echo "Running examples..."
	@for example in examples/*; do \
		if [ -d "$$example" ]; then \
			go run "$$example"/*.go || exit 1; \
		fi; \
	done

benchmark:
	@echo "Running benchmarks..."
	go test -bench=. ./benchmark

# validate-all: comprehensive validation before commit/push
validate-all: lint test security examples
	@echo "✓ All validations passed"

# Tidy up go.mod and go.sum
tidy:
	go mod tidy

clean:
	rm -f coverage.out codeql-report.sarif
	rm -rf db/

