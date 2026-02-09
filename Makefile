# Makefile for cfssl_trust local development
# Provides Docker-based release workflow with volume mounting for new certs

IMAGE_NAME := cfssl-trust-release
CONTAINER_NAME := cfssl-trust-release-container

# Environment variables passed to release.sh
EXPIRATION_WINDOW ?= 0h
NOGIT ?=
ALLOW_SKIP_PR ?=

# Certificate files (relative to repo root, mounted automatically)
NEW_ROOTS ?=
NEW_INTERMEDIATES ?=

.PHONY: build run release shell clean help

help:
	@echo "cfssl_trust Docker-based release workflow"
	@echo ""
	@echo "Usage:"
	@echo "  make build                    Build the Docker image"
	@echo "  make release                  Run release.sh in Docker (NOGIT=1 by default)"
	@echo "  make release-full             Run full release with git operations"
	@echo "  make shell                    Open a shell in the container"
	@echo "  make clean                    Remove Docker image and containers"
	@echo ""
	@echo "Adding new certificates:"
	@echo "  make release NEW_ROOTS=NEW_ROOTS.pem NEW_INTERMEDIATES=NEW_INTERMEDIATES.pem"
	@echo ""
	@echo "Environment variables:"
	@echo "  EXPIRATION_WINDOW    Minimum cert validity (default: 0h)"
	@echo "  NEW_ROOTS            Path to new root certs file (e.g., NEW_ROOTS.pem)"
	@echo "  NEW_INTERMEDIATES    Path to new intermediate certs file (e.g., NEW_INTERMEDIATES.pem)"
	@echo "  NOGIT                Set to skip git operations (default: 1 for 'release' target)"
	@echo ""

# Build the Docker image with the latest cfssl_trust code
build:
	docker build -t $(IMAGE_NAME) .

# Run release.sh with NOGIT=1 (safe for local testing)
release: build
	docker run --rm \
		-v $(CURDIR):/cfssl_trust \
		-w /cfssl_trust \
		-e EXPIRATION_WINDOW=$(EXPIRATION_WINDOW) \
		-e ALLOW_SKIP_PR=$(ALLOW_SKIP_PR) \
		-e NOGIT=1 \
		$(if $(NEW_ROOTS),-e NEW_ROOTS=$(NEW_ROOTS)) \
		$(if $(NEW_INTERMEDIATES),-e NEW_INTERMEDIATES=$(NEW_INTERMEDIATES)) \
		$(IMAGE_NAME) ./release.sh

# Run full release with git operations (use with caution)
release-full: build
	docker run --rm \
		-v $(CURDIR):/cfssl_trust \
		-w /cfssl_trust \
		-e EXPIRATION_WINDOW=$(EXPIRATION_WINDOW) \
		-e ALLOW_SKIP_PR=$(ALLOW_SKIP_PR) \
		$(if $(NEW_ROOTS),-e NEW_ROOTS=$(NEW_ROOTS)) \
		$(if $(NEW_INTERMEDIATES),-e NEW_INTERMEDIATES=$(NEW_INTERMEDIATES)) \
		$(IMAGE_NAME) ./release.sh

# Open an interactive shell in the container for debugging
shell: build
	docker run --rm -it \
		-v $(CURDIR):/cfssl_trust \
		-w /cfssl_trust \
		$(IMAGE_NAME) /bin/bash

# Clean up Docker resources
clean:
	-docker rmi $(IMAGE_NAME) 2>/dev/null || true
	-docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
