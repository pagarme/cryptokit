pkgs := $(shell go list $(shell glide nv) | tr "\n" "," | rev | cut -c2- | rev)
gotemplate := {{if .TestGoFiles}}go test -v -timeout=120s -covermode count -coverprofile={{.Name}}.coverprofile -coverpkg=$(pkgs) {{.ImportPath}}{{end}}

travis-deps:
	@go get github.com/mattn/goveralls
	@go get github.com/wadey/gocovmerge
	@go get github.com/alecthomas/gometalinter
	@curl https://glide.sh/get | sh
	@glide install
	@gometalinter -i

test:
	@echo Running tests
	@go list -f '$(gotemplate)' $(shell glide nv) | xargs -I cmd bash -c cmd
	@gocovmerge *.coverprofile > coverage.out

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
