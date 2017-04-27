package main

import (
	"fmt"
)

type TokenType uint

const (
	_ TokenType = iota

	ArgumentName
	Identifier
	StringLiteral
	HexLiteral
	DecimalLiteral
	PathLiteral
	RightParens
	LeftParens
	EOF

	Unknown
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
