package main

import (
	"fmt"
)

//go:generate stringer -type=TokenType
type TokenType uint

const (
	Unknown TokenType = iota

	ArgumentName
	Identifier
	StringLiteral
	HexLiteral
	DecimalLiteral
	PathLiteral
	LeftParens
	RightParens

	EOF
)

var ValueTokenTypes = []TokenType{
	Identifier,
	StringLiteral,
	HexLiteral,
	DecimalLiteral,
	PathLiteral,
}

type Position struct {
	Line, Column int
}

type Token struct {
	Type  TokenType
	Text  string
	Start Position
	End   Position
}

func (t *Token) String() string {
	return fmt.Sprintf("%s at %d:%d (%s)", t.Type, t.Start.Line, t.Start.Column, t.Text)
}
