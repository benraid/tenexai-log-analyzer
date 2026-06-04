# Multi-stage build: compile in a fat builder image, then copy the static binary
# into a tiny distroless image. Result is a ~20MB final image with no shell.
FROM golang:1.26-alpine AS builder
WORKDIR /src

# Cache deps separately so code changes don't re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 produces a fully static binary that runs on any glibc/musl/scratch base.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/server /app/server
COPY db/migrations /app/db/migrations
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
