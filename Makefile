travis-deps:
	@go get github.com/mattn/goveralls
	@go get github.com/wadey/gocovmerge
	@curl https://glide.sh/get | sh
	@glide up

test:
	@echo Running tests
	$(eval PKGS := $(shell go list ./... | grep -v /vendor/))
	$(eval PKGS_DELIM := $(shell echo $(PKGS) | sed -e 's/ /,/g'))
	@go list -f '{{if or (len .TestGoFiles) (len .XTestGoFiles)}}go test -test.v -test.timeout=120s -covermode=count -coverprofile={{.Name}}_{{len .Imports}}_{{len .Deps}}.coverprofile -coverpkg $(PKGS_DELIM) {{.ImportPath}}{{end}}' $(PKGS) | xargs -I {} bash -c {}
	@gocovmerge `ls *.coverprofile` > coverage.out
	@rm *.coverprofile

.PHONY: test trevis-deps
