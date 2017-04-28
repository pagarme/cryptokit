package main

import (
	"fmt"
	"reflect"

	"github.com/pagarme/cryptokit"
)

type echoArgs struct {
	Text string `cmd:",primary"`
}

var commands = map[string]interface{}{}

func init() {
	RegisterType(&cryptokit.Aes{})
	RegisterType(&cryptokit.Des{})
	RegisterType(&cryptokit.Tdes{})
	RegisterType(&cryptokit.Cbc{})
	RegisterType(&cryptokit.Ecb{})
	RegisterType(&cryptokit.Gcm{})
	RegisterType(&cryptokit.Sha1{})
	RegisterType(&cryptokit.Sha256{})
	RegisterType(&cryptokit.Sha512{})
	RegisterType(&cryptokit.Hmac{})
	RegisterType(&cryptokit.Random{})
	RegisterType(&cryptokit.Dukpt{})
	RegisterType(&cryptokit.FixedKey{})

	RegisterCommand("echo", func(e *echoArgs) (string, error) {
		fmt.Printf("%s\n", e.Text)
		return "", nil
	})
}

func RegisterCommand(name string, command interface{}) {
	commands[name] = command
}

func RegisterType(val interface{}) {
	typ := reflect.TypeOf(val)

	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	RegisterTypeWithName(transformName(typ.Name()), val)
}

func RegisterTypeWithName(name string, val interface{}) {
	typ := reflect.TypeOf(val)

	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	RegisterCommand(name, func(c *Command) (interface{}, error) {
		val := reflect.New(typ)
		err := unmarshalCommand(val, c)

		if err != nil {
			return nil, err
		}

		return val.Elem().Interface(), nil
	})
}
