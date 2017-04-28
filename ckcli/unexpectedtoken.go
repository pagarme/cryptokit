package main

import (
	"fmt"
	"strings"
)

type UnexpectedToken struct {
	Expected  []TokenType
	Current   *Token
	LookAhead *Token
}

func (u UnexpectedToken) Error() string {
	types := make([]string, len(u.Expected))

	for i, e := range u.Expected {
		types[i] = e.String()
	}

	expected := strings.Join(types, ", ")

	return fmt.Sprintf("Unexpected token at %d:%d, expected %s. (current = %s, la = %s)", u.Current.Start.Line, u.Current.Start.Column, expected, u.Current.String(), u.LookAhead.String())
}

func (u UnexpectedToken) String() string {
	return u.Error()
}
