OUT := bin

.PHONY: build run test vet tidy clean docker resident-image

build: ## build binaries into bin/
	go build -trimpath -o $(OUT)/veild ./cmd/veild
	go build -trimpath -o $(OUT)/veil-agent ./cmd/veil-agent
	go build -trimpath -o $(OUT)/veil-resident ./cmd/veil-resident

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

resident-image: ## build the resident image (veil-resident:dev)
	docker build -f deploy/Dockerfile.resident -t veil-resident:dev .
