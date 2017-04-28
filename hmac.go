package cryptokit

type Hmac struct {
	Underlying Mechanism `cmd:",primary"`
}

func (m Hmac) Name() string {
	return "hmac-" + m.Underlying.Name()
}
