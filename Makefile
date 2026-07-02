OUT := bin

.PHONY: build run test vet tidy clean docker

build: ## build both binaries into bin/
	go build -trimpath -o $(OUT)/veild ./cmd/veild
	go build -trimpath -o $(OUT)/veil-agent ./cmd/veil-agent

run: ## run the host-side control plane (http://localhost:8080)
	go run ./cmd/veild

test: ## run all tests
	go test ./...

vet: ## static checks (swap for golangci-lint later)
	go vet ./...

tidy: ## sync go.mod / go.sum
	go mod tidy

clean: ## remove build artifacts
	rm -rf $(OUT)

docker: ## build the container image
	docker build -f deploy/Dockerfile -t veil:dev .
