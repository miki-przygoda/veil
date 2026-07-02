# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.22-alpine AS build
WORKDIR /src

# Cache deps first. go.sum may not exist yet (stdlib-only); the glob tolerates that.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/veild ./cmd/veild

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/veild /app/veild
COPY web /app/web
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/veild"]
