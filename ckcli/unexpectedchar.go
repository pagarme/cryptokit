package main

import "fmt"

type UnexpectedChar struct {
	Expected  string
	Position  Position
	Current   rune
	LookAhead rune
}

func (u UnexpectedChar) Error() string {
	return fmt.Sprintf("Unexpected character at %d:%d, expected %s. (current = %c, la = %c)", u.Position.Line, u.Position.Column, u.Expected, u.Current, u.LookAhead)
}
