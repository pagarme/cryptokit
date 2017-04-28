package main

import (
	"fmt"
	"os"

	"github.com/docopt/docopt.go"
	"github.com/pagarme/cryptokit"

	_ "github.com/pagarme/cryptokit/soft"
)

var session cryptokit.Session

func main() {
	usage := `Cryptokit CLI
	
Usage:
	ckcli <url>
	
Options:
	-h --help	Show this text.
	--version	Show version.`

	args, err := docopt.Parse(usage, nil, true, "Cryptokit", false)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
		return
	}

	url, ok := args["<url>"]

	if !ok {
		fmt.Println(usage)
		os.Exit(1)
		return
	}

	p, err := cryptokit.Create(url.(string))

	if err != nil {
		fmt.Printf("Error creating provider: %s\n", err)
		os.Exit(1)
		return
	}

	session, err = p.OpenSession()

	if err != nil {
		fmt.Printf("Error opening session: %s\n", err)
		os.Exit(1)
		return
	}

	err = runRepl()

	if err != nil {
		fmt.Printf("Error running repl: %s\n", err)
		os.Exit(1)
		return
	}

	os.Exit(0)
}
