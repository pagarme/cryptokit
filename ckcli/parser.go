package main

type Parser struct {
	scanner *Scanner
	cur     *Token
	la      *Token
}

func NewParser(s *Scanner) *Parser {
	return &Parser{
		scanner: s,
	}
}

func (p *Parser) Parse() (*Command, error) {
	if err := p.next(); err != nil {
		return nil, err
	}

	cmd, ok, err := p.matchCommand()

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, p.unexpectedToken()
	}

	return cmd, nil
}

func (p *Parser) matchCommand() (*Command, bool, error) {
	var name *Token

	if ok, err := p.match(&name, Identifier); err != nil || !ok {
		return nil, false, err
	}

	cmd := NewCommand(name.Text)

	if value, ok, err := p.matchValue(); err != nil {
		return nil, false, err
	} else if ok {
		cmd.Primary = value
	}

	for {
		var name *Token

		if ok, err := p.match(&name, ArgumentName); err != nil {
			return nil, false, err
		} else if !ok {
			break
		}

		if value, ok, err := p.matchValue(); err != nil {
			return nil, false, err
		} else if ok {
			cmd.Parameters[name.Text] = value
		} else {
			return nil, false, p.unexpectedToken()
		}
	}

	return cmd, true, nil
}

func (p *Parser) matchValue() (interface{}, bool, error) {
	var value interface{}

	switch p.cur.Type {
	case LeftParens:
		if err := p.mustMatch(nil, LeftParens); err != nil {
			return nil, false, err
		}

		cmd, ok, err := p.matchCommand()

		if err != nil {
			return nil, false, err
		}

		if !ok {
			return nil, false, p.unexpectedToken()
		}

		value = cmd

		if err := p.mustMatch(nil, RightParens); err != nil {
			return nil, false, err
		}

	case Identifier:
		fallthrough
	case StringLiteral:
		fallthrough
	case HexLiteral:
		fallthrough
	case DecimalLiteral:
		fallthrough
	case PathLiteral:
		var tk *Token

		if err := p.mustMatch(&tk, p.cur.Type); err != nil {
			return nil, false, err
		}

		value = tk

	default:
		return nil, false, nil
	}

	return value, true, nil
}

func (p *Parser) match(tk **Token, typ ...TokenType) (bool, error) {
	ok := false

	for _, t := range typ {
		if p.cur.Type == t {
			ok = true
			break
		}
	}

	if !ok {
		return false, nil
	}

	if tk != nil {
		*tk = p.cur
	}

	return true, p.next()
}

func (p *Parser) mustMatch(tk **Token, typ ...TokenType) error {
	ok, err := p.match(tk, typ...)

	if err != nil {
		return err
	}

	if !ok {
		return p.unexpectedToken(typ...)
	}

	return nil
}

func (p *Parser) next() error {
	t, err := p.scanner.Next()

	if err != nil {
		return err
	}

	if p.la == nil {
		p.la = t
		return p.next()
	}

	p.cur = p.la
	p.la = t

	return nil
}

func (p *Parser) unexpectedToken(expected ...TokenType) error {
	return UnexpectedToken{
		Expected:  expected,
		Current:   p.cur,
		LookAhead: p.la,
	}
}
