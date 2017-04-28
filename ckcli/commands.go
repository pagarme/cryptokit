package main

import (
	"fmt"
	"reflect"

	"github.com/pagarme/cryptokit"
)

type echoArgs struct {
	Text    string `cmd:",primary"`
	TheArg2 string
}

var commands = map[string]interface{}{}

func init() {
	RegisterType(&cryptokit.Aes{})
	RegisterType(&cryptokit.Cbc{})

	RegisterCommand("echo", func(e *echoArgs) (string, error) {
		fmt.Printf("%s%s\n", e.Text, e.TheArg2)
		return "", nil
	})
}

func RegisterCommand(name string, command interface{}) {
	fmt.Printf("Registered %s\n", name)

	commands[name] = command
}

func RegisterType(val interface{}) {
	typ := reflect.TypeOf(val)

	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	RegisterCommand(transformName(typ.Name()), func(c *Command) (interface{}, error) {
		val := reflect.New(typ)
		err := unmarshalCommand(val, c)

		if err != nil {
			return nil, err
		}

		return val.Interface(), nil
	})
}
