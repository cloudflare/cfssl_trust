# Dockerfile for cfssl_trust release environment
# Provides Go 1.24, certdump, cfssl tools, and cfssl-trust

FROM golang:1.24-bookworm

# Install git and update CA certificates
RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Allow git to work with mounted directories (different ownership)
RUN git config --global --add safe.directory /cfssl_trust

# Install certdump, pinning to v1.7.7 to avoid cert issues in later versions
RUN go install git.wntrmute.dev/kyle/goutils/cmd/certdump@v1.7.7

# Install cfssl tools
RUN go install github.com/cloudflare/cfssl/cmd/...

# Set working directory
WORKDIR /cfssl_trust

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build and install cfssl-trust from local source
RUN go install ./cmd/cfssl-trust

# Ensure binaries are in PATH
ENV PATH="/go/bin:${PATH}"

# Default command
CMD ["./release.sh"]
