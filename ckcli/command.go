package main

type Command struct {
	Name       string
	Primary    interface{}
	Parameters map[string]interface{}
}

func NewCommand(name string) *Command {
	return &Command{
		Name:       name,
		Parameters: make(map[string]interface{}),
	}
}
