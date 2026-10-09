BIN     := sbomcmp
PKG     := github.com/junseok-seo/sbomcmp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test demo clean release fmt

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

fmt:
	gofmt -l -w .

test:
	go vet ./...
	go test ./...

# End-to-end run with the mock generators and the offline vulnerability fixture.
# Nothing is installed or contacted over the network.
demo: build
	./$(BIN) scan --bin $(CURDIR)/testdata/mock-bin --only syft,cdxgen,trivy \
	  --vuln-fixture $(CURDIR)/testdata/fixtures/vulns.json -o /tmp/sbomcmp-demo.json testdata/sample-project
	./$(BIN) report -i /tmp/sbomcmp-demo.json
	@echo; echo "open the viewer:  ./$(BIN) ui -i /tmp/sbomcmp-demo.json"

release:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)_linux_amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)_linux_arm64 .
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)_darwin_amd64 .
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)_darwin_arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)_windows_amd64.exe .
	cd dist && shasum -a 256 * > SHA256SUMS

clean:
	rm -rf $(BIN) dist sbomcmp.json sbomcmp.raw
