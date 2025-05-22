# Build stage
FROM golang:1.24-bookworm AS builder

LABEL maintainer="Sai Sanjay"

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a  -installsuffix cgo -o main ./cmd/clamav

# Final stage
FROM alpine:3.19

# Add retry logic and better error handling for package installation
RUN set -eux; \
    # Update package index
    apk update; \
    # Install packages with retry logic
    for i in 1 2 3; do \
        apk --no-cache add ca-certificates tzdata wget && break || \
        (echo "Attempt $i failed, retrying..." && sleep $((i * 2))); \
    done; \
    # Verify installation
    which wget || (echo "wget installation failed" && exit 1)

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy .env file if it exists
COPY --from=builder /app/.env* ./

# Set default environment variables
ENV NODE_ENV=production \
    CLAMD_IP=clamd \
    APP_FORM_KEY=FILES \
    APP_PORT=3000 \
    APP_MAX_FILE_SIZE=26214400 \
    APP_MAX_FILES_NUMBER=4 \
    CLAMD_PORT=3310 \
    CLAMD_TIMEOUT=60000 \
    APP_MORGAN_LOG_FORMAT=combined \
    REDIS_URL=redis://redis:6379 \
    JOB_EXPIRATION=3600

# Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -S -D -H -u 1001 -h /root -s /sbin/nologin -G appuser appuser

# Change ownership
RUN chown -R appuser:appuser /root

USER appuser

EXPOSE 3000

CMD ["./main"]
