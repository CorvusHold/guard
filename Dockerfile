# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILDPLATFORM
ARG TARGETPLATFORM

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code (excludes items in .dockerignore)
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /guard ./cmd/api

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 guard && \
    adduser -u 1000 -G guard -s /bin/sh -D guard

WORKDIR /app

# Copy binary from builder
COPY --from=builder /guard /usr/local/bin/guard

# Copy migrations for runtime migration support
COPY --from=builder /app/migrations ./migrations

# Set ownership
RUN chown -R guard:guard /app

USER guard

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/readyz || exit 1

ENTRYPOINT ["guard"]
