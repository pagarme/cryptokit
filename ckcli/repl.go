package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"reflect"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	"github.com/davecgh/go-spew/spew"
	"github.com/fatih/camelcase"
)

func runRepl() error {
	user, err := user.Current()

	if err != nil {
		return err
	}

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31m»\033[0m ",
		HistoryFile:     path.Join(user.HomeDir, ".ckcli-history"),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})

	if err != nil {
		return err
	}

	defer func() {
		_ = l.Close()
	}()

	log.SetOutput(os.Stderr)

	for {
		line, err := l.Readline()

		if err != nil {
			return err
		}

		err = runLine(line)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
	}
}

func runLine(line string) error {
	reader := strings.NewReader(line)
	scanner := NewScanner(reader)
	parser := NewParser(scanner)

	cmd, err := parser.Parse()

	if err != nil {
		return err
	}

	result, err := executeCommand(cmd)

	if err != nil {
		return err
	}

	if result != nil {
		switch v := result.(type) {
		case string:
			fmt.Printf("%s\n", v)
		case fmt.Stringer:
			fmt.Printf("%s\n", v)
		default:
			spew.Dump(v)
		}
	}

	return nil
}

func executeCommand(cmd *Command) (interface{}, error) {
	fn, ok := commands[cmd.Name]

	if !ok {
		return nil, fmt.Errorf("Unknown command %s", cmd.Name)
	}

	val := reflect.ValueOf(fn)
	typ := val.Type()

	if typ.NumIn() != 1 || typ.NumOut() != 2 {
		return nil, fmt.Errorf("Invalid function declaration")
	}

	if !typ.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return nil, fmt.Errorf("Invalid function declaration")
	}

	argTyp := typ.In(0)

	if argTyp.Kind() == reflect.Ptr {
		argTyp = argTyp.Elem()
	}

	arg := reflect.New(argTyp)

	err := unmarshalCommand(arg, cmd)

	if err != nil {
		return nil, err
	}

	result := val.Call([]reflect.Value{arg})

	if !result[1].IsNil() {
		return nil, result[1].Interface().(error)
	}

	return result[0].Interface(), nil
}

func unmarshalCommand(val reflect.Value, cmd *Command) error {
	typ := val.Type()

	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		val = val.Elem()
	}

	if typ == reflect.TypeOf(cmd).Elem() {
		val.Set(reflect.ValueOf(cmd).Elem())
		return nil
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		if field.Anonymous {
			err := unmarshalCommand(val.Field(i), cmd)

			if err != nil {
				return err
			}

			continue
		}

		tag := field.Tag.Get("cmd")

		values := strings.Split(tag, ",")
		name := values[0]

		if name == "" {
			name = transformName(field.Name)
		}

		if len(values) > 1 && values[1] == "primary" {
			if cmd.Primary != nil {
				err := unmarshalValue(val.Field(i), cmd.Primary)

				if err != nil {
					return err
				}
			}
		} else {
			arg, ok := cmd.Parameters[name]

			if ok {
				err := unmarshalValue(val.Field(i), arg)

				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func unmarshalValue(val reflect.Value, input interface{}) error {
	switch v := input.(type) {
	case *Command:
		result, err := executeCommand(v)

		if err != nil {
			return err
		}

		val.Set(reflect.ValueOf(result))
	case *Token:
		err := extractTokenValue(v, val.Addr().Interface())

		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Invalid token as parameter")
	}

	return nil
}

func extractTokenValue(t *Token, value interface{}) error {
	switch v := value.(type) {
	case *int:
		var data string

		err := extractString(t, &data)

		if err != nil {
			return err
		}

		base := 10

		if t.Type == HexLiteral {
			base = 16
		}

		i, err := strconv.ParseInt(data, base, 32)

		if err != nil {
			return err
		}

		*v = int(i)

	case *uint:
		var data string

		err := extractString(t, &data)

		if err != nil {
			return err
		}

		base := 10

		if t.Type == HexLiteral {
			base = 16
		}

		i, err := strconv.ParseUint(data, base, 32)

		if err != nil {
			return err
		}

		*v = uint(i)

	case *bool:
		var data string

		err := extractString(t, &data)

		if err != nil {
			return err
		}

		i, err := strconv.ParseBool(data)

		if err != nil {
			return err
		}

		*v = i

	case *string:
		return extractString(t, v)

	case *[]byte:
		return extractBytes(t, v)

	case *io.Reader:
		return extractReader(t, v)

	case *io.Writer:
		return extractWriter(t, v)

		// default:
		// 	return fmt.Errorf("Invalid struct type")
	}

	return nil
}

func extractString(t *Token, v *string) error {
	switch t.Type {
	case PathLiteral:
		data, err := ioutil.ReadFile(t.Text)

		if err != nil {
			return err
		}

		*v = string(data)
	default:
		*v = t.Text
	}

	return nil
}

func extractBytes(t *Token, v *[]byte) error {
	switch t.Type {
	case HexLiteral:
		data, err := hex.DecodeString(t.Text)

		if err != nil {
			return err
		}

		*v = data
	case Identifier:
		fallthrough
	case StringLiteral:
		*v = []byte(t.Text)
	case PathLiteral:
		data, err := ioutil.ReadFile(t.Text)

		if err != nil {
			return err
		}

		*v = data
	default:
		return fmt.Errorf("Invalid parameter")
	}

	return nil
}

func extractReader(t *Token, v *io.Reader) error {
	switch t.Type {
	case HexLiteral:
		data, err := hex.DecodeString(t.Text)

		if err != nil {
			return err
		}

		*v = bytes.NewBuffer(data)
	case Identifier:
		fallthrough
	case StringLiteral:
		*v = strings.NewReader(t.Text)
	case PathLiteral:
		// #nosec
		file, err := os.OpenFile(t.Text, os.O_RDONLY, 0755)

		if err != nil {
			return err
		}

		*v = file
	default:
		return fmt.Errorf("Invalid parameter")
	}

	return nil
}

func extractWriter(t *Token, v *io.Writer) error {
	switch t.Type {
	case PathLiteral:
		// #nosec
		file, err := os.OpenFile(t.Text, os.O_RDWR|os.O_CREATE, 0755)

		if err != nil {
			return err
		}

		*v = file
	default:
		return fmt.Errorf("Invalid parameter")
	}

	return nil
}

func transformName(name string) string {
	parts := camelcase.Split(name)

	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}

	return strings.Join(parts, "-")
}
