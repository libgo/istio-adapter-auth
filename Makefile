VERSION=v0.1

bin: gen build
pub: bin image release

gen:
	go generate ./...

build:
	CGO_ENABLED=0 GOOS=linux go build -ldflags '-w -s -X "istio.io/istio/mixer/adapter/auth.version=${VERSION}"' -o bin/auth cmd/main.go

image:
	docker build -t sdrzlyz/istio-auth-adapter:${VERSION} .

release:
	docker push sdrzlyz/istio-auth-adapter:${VERSION}

build-mac:
	CGO_ENABLED=0 go build -o bin/auth cmd/main.go
