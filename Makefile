.PHONY: dev test image doc gen

APP_NAME := ot-auth
APP_PATH := github.com/open-trust/ot-auth
APP_VERSION := $(shell git describe --tags --always --match "v[0-9]*")

gen:
	@gqlgenc

dev:
	@CONFIG_FILE_PATH=${PWD}/config/default.yaml APP_ENV=development go run main.go

test:
	@CONFIG_FILE_PATH=${PWD}/config/test.yaml APP_ENV=testing go test -v ./...

doc:
	widdershins --language_tabs 'shell:Shell' 'http:HTTP' --summary doc/openapi.yaml -o doc/openapi.md

BUILD_TIME := $(shell date -u +"%FT%TZ")
BUILD_COMMIT := $(shell git rev-parse HEAD)

.PHONY: build build-tool
build:
	@mkdir -p ./dist
	GO111MODULE=on go build -ldflags "-X ${APP_PATH}/src/conf.AppName=${APP_NAME} \
	-X ${APP_PATH}/src/conf.AppVersion=${APP_VERSION} \
	-X ${APP_PATH}/src/conf.BuildTime=${BUILD_TIME} \
	-X ${APP_PATH}/src/conf.GitSHA1=${BUILD_COMMIT}" \
	-o ./dist/app main.go
build-linux:
	@mkdir -p ./dist
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X ${APP_PATH}/src/conf.AppName=${APP_NAME} \
	-X ${APP_PATH}/src/conf.AppVersion=${APP_VERSION} \
	-X ${APP_PATH}/src/conf.BuildTime=${BUILD_TIME} \
	-X ${APP_PATH}/src/conf.GitSHA1=${BUILD_COMMIT}" \
	-o ./dist/app main.go

PKG_LIST := $(shell go list ./... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/)

.PHONY: coverhtml
coverhtml:
	@mkdir -p coverage
	@CONFIG_FILE_PATH=${PWD}/config/test.yaml go test -coverprofile=coverage/cover.out ./...
	@go tool cover -html=coverage/cover.out -o coverage/coverage.html
	@go tool cover -func=coverage/cover.out | tail -n 1

DOCKER_IMAGE_TAG := ${APP_NAME}:latest
.PHONY: image
image:
	docker build --rm -t ${DOCKER_IMAGE_TAG} .
