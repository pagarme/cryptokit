package main

import (
	"fmt"
)

type echoArgs struct {
	Text string `cmd:""`
	Arg2 string `cmd:"arg2"`
}

var commands = map[string]interface{}{}

func init() {
	RegisterCommand("echo", func(e *echoArgs) (string, error) {
		fmt.Printf("%s%s\n", e.Text, e.Arg2)
		return "", nil
	})
}

func RegisterCommand(name string, command interface{}) {
	commands[name] = command
}
