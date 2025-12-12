DOCKER_USER ?= default_user
IMAGE_NAME ?= default_mail_api_image_name

GO_OS ?= linux
GO_ARCH ?= amd64
BUILD_OUTPUT = server
MAIN_FILE = main.go
PUSH_TAG ?= latest

FULL_IMAGE_NAME = $(DOCKER_USER)/$(IMAGE_NAME):$(PUSH_TAG)

.PHONY: all build docker-build docker-push clean run

all: docker-push

build:
	@echo "Building Go binary for $(GO_OS)/$(GO_ARCH)..."
	CGO_ENABLED=0 GOOS=$(GO_OS) GOARCH=$(GO_ARCH) go build -o $(BUILD_OUTPUT) $(MAIN_FILE)
	@echo "SUCCESS! Built $(BUILD_OUTPUT)"

docker-build: build
	@echo "Building Docker image: $(FULL_IMAGE_NAME)"
	docker build -t $(FULL_IMAGE_NAME) .
	@echo "SUCCESS! Built Docker image"

docker-push: docker-build
	@echo "Pushing image to registry: $(FULL_IMAGE_NAME)\n Make sure youre logged in to docker in case this does not work..."
	docker push $(FULL_IMAGE_NAME)
	@echo "SUCCESS! Pushed $(FULL_IMAGE_NAME)"

clean:
	@echo "Cleaning up build artifacts..."
	rm -f $(BUILD_OUTPUT)

run:
	@echo "Running local build..."
	go run $(MAIN_FILE)
