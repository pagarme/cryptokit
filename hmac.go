package cryptokit

type Hmac struct {
	Underlying Mechanism
}

func (m Hmac) Name() string {
	return "hmac-" + m.Underlying.Name()
}
