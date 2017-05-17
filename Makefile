deps:
	@echo Getting dependencies
	@go get golang.org/x/tools/cmd/cover
	@go get github.com/mattn/goveralls
	@go get github.com/wadey/gocovmerge
	@go get github.com/boltdb/bolt
	@go get github.com/hashicorp/vault/api
	@go get github.com/chzyer/readline
	@go get github.com/davecgh/go-spew/spew
	@go get github.com/docopt/docopt-go
	@go get github.com/fatih/camelcase
	@go get github.com/SSSaaS/sssa-golang
	@go get github.com/buger/goterm
	@go get github.com/tucnak/climax
	@go get github.com/stretchr/testify/assert

test: deps
	@echo Running tests
	$(eval PKGS := $(shell go list ./... | grep -v /vendor/))
	$(eval PKGS_DELIM := $(shell echo $(PKGS) | sed -e 's/ /,/g'))
	@go list -f '{{if or (len .TestGoFiles) (len .XTestGoFiles)}}go test -test.v -test.timeout=120s -covermode=count -coverprofile={{.Name}}_{{len .Imports}}_{{len .Deps}}.coverprofile -coverpkg $(PKGS_DELIM) {{.ImportPath}}{{end}}' $(PKGS) | xargs -I {} bash -c {}
	@gocovmerge `ls *.coverprofile` > coverage.out
	@rm *.coverprofile

.PHONY: test

