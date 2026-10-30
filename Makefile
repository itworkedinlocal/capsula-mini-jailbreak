PYTHON ?= python3
export CGO_ENABLED ?= 0

.PHONY: build build-windows test test-full vet check-resources release release-windows
build:
	go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/capsula ./cmd/capsula

build-windows:
	GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/capsula.exe ./cmd/capsula

test:
	go test ./... -count=1

test-full: check-resources test

vet:
	go vet ./...
	GOOS=windows GOARCH=amd64 go vet ./...

check-resources:
	$(PYTHON) -B scripts/resources.py --check

release:
	$(PYTHON) -B scripts/package.py --target linux

release-windows:
	$(PYTHON) -B scripts/package.py --target windows
