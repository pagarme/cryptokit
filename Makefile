travis-deps:
	@go get github.com/mattn/goveralls
	@go get github.com/wadey/gocovmerge
	@go get github.com/alecthomas/gometalinter
	@curl https://glide.sh/get | sh
	@glide install
	@gometalinter -i

test:
	@echo Running tests
	$(eval PKGS := $(shell go list ./... | grep -v /vendor/))
	$(eval PKGS_DELIM := $(shell echo $(PKGS) | sed -e 's/ /,/g'))
	@go list -f '{{if or (len .TestGoFiles) (len .XTestGoFiles)}}go test -test.v -test.timeout=120s -covermode=count -coverprofile={{.Name}}_{{len .Imports}}_{{len .Deps}}.coverprofile -coverpkg $(PKGS_DELIM) {{.ImportPath}}{{end}}' $(PKGS) | xargs -I {} bash -c {}
	@gocovmerge `ls *.coverprofile` > coverage.out
	@rm *.coverprofile

metalinter:
	@gometalinter \
		--config gometalinter.json \
		--cyclo-over 16 \
		--min-confidence 1.1 \
		--deadline 120s \
		$(glide nv)

metalinter-full:
	@gometalinter \
		--enable-all \
		--deadline 120s \
		$(glide nv)

.PHONY: test trevis-deps metalinter metalinter-full
