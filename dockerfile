# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod ./
RUN go mod download || true

# Copy source code
COPY . .

# Build the binary
RUN go build -o prometheus-teams-proxy main.go

# Final stage
FROM alpine:3.21

# Add ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/prometheus-teams-proxy .

# Expose port (matches the default in code)
EXPOSE 8080

# Set default env var (can be overridden)
ENV PORT=8080

# Run the binary
ENTRYPOINT ["./prometheus-teams-proxy"]
