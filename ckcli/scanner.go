package main

import (
	"bufio"
	"fmt"
	"io"
	"unicode"
)

var EOFChar = '\x00'

type Scanner struct {
	reader *bufio.Reader
	cur    rune
	la     rune
	line   int
	column int
}

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{
		reader: bufio.NewReader(r),
		line:   1,
		column: -1,
	}
}

func (s *Scanner) Next() (*Token, error) {
	err := s.skipWhitespace()

	if err != nil {
		return nil, err
	}

	token := &Token{
		Type:  Unknown,
		Start: s.Position(),
	}

	if s.cur == EOFChar {
		token.Type = EOF
	} else if unicode.IsSpace(s.cur) {
		return s.Next()
	} else if unicode.IsLetter(s.cur) {
		err = s.scanIdentifier(token)
	} else if unicode.IsNumber(s.cur) {
		err = s.scanNumber(token)
	} else {
		switch s.cur {
		case '@':
			err = s.scanPath(token)
		case '"':
			err = s.scanString(token)
		case '(':
			token.Type = LeftParens
		case ')':
			token.Type = RightParens
		case '-':
			if s.la == '-' {
				err = s.scanArgumentName(token)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	token.End = s.Position()

	return token, nil
}

func (s *Scanner) Position() Position {
	return Position{
		Line:   s.line,
		Column: s.column,
	}
}

func (s *Scanner) scanArgumentName(t *Token) error {
	if err := s.match('-'); err != nil {
		return err
	}

	if err := s.match('-'); err != nil {
		return err
	}

	err := s.scanCore(t, isIdentifier)

	if err != nil {
		return err
	}

	t.Type = ArgumentName

	return nil
}

func (s *Scanner) scanIdentifier(t *Token) error {
	err := s.scanCore(t, isIdentifier)

	if err != nil {
		return err
	}

	t.Type = getIdentifierType(t.Text)

	return nil
}

func (s *Scanner) scanPath(t *Token) error {
	if err := s.match('@'); err != nil {
		return err
	}

	if s.cur == '"' {
		err := s.scanString(t)

		if err != nil {
			return err
		}
	} else {
		err := s.scanCore(t, isWhitespace)

		if err != nil {
			return err
		}
	}

	t.Type = PathLiteral

	return nil
}

func (s *Scanner) scanString(t *Token) error {
	if err := s.match('"'); err != nil {
		return err
	}

	err := s.scanCore(t, isString)

	if err != nil {
		return err
	}

	t.Type = StringLiteral

	return nil
}

func (s *Scanner) scanNumber(t *Token) error {
	var test func(rune) bool

	isHex := false

	if s.cur == '0' {
		if s.la == 'x' || s.la == 'X' {
			isHex = true

			if err := s.nextChar(); err != nil {
				return err
			}

			if err := s.nextChar(); err != nil {
				return err
			}
		}
	}

	if isHex {
		test = isHexChar
		t.Type = HexLiteral
	} else {
		test = unicode.IsDigit
		t.Type = DecimalLiteral
	}

	return s.scanCore(t, test)
}

func (s *Scanner) scanCore(t *Token, test func(rune) bool) error {
	acc := ""

	for {
		acc += string(s.cur)

		if !test(s.la) {
			break
		}

		if err := s.nextChar(); err != nil {
			return err
		}
	}

	t.Text = acc

	return nil
}

func (s *Scanner) match(r rune) error {
	if s.cur != r {
		return s.unexpectedChar(fmt.Sprintf("'%c'", r))
	}

	return s.nextChar()
}

func (s *Scanner) skipWhitespace() error {
	for {
		err := s.nextChar()

		if err != nil {
			return err
		}

		if !isWhitespace(s.cur) {
			break
		}
	}

	return nil
}

func (s *Scanner) nextChar() error {
	r, _, err := s.reader.ReadRune()

	if err == io.EOF {
		r = EOFChar
	} else if err != nil {
		return err
	}

	s.column++
	s.cur = s.la
	s.la = r

	if s.column == 0 {
		return s.nextChar()
	}

	if s.cur == '\n' {
		s.column = 1
		s.line++
		return s.nextChar()
	}

	return nil
}

func (s *Scanner) unexpectedChar(expected string) error {
	return UnexpectedChar{
		Expected:  expected,
		Position:  s.Position(),
		Current:   s.cur,
		LookAhead: s.la,
	}
}

func isWhitespace(r rune) bool {
	return r == ' ' || r == '\n' || r == '\r' || r == '\t'
}

func isString(r rune) bool {
	return r != '"'
}

func isIdentifier(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_'
}

func isHexChar(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func getIdentifierType(text string) TokenType {
	return Identifier
}
