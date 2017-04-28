package cryptokit

type Cbc struct {
	Underlying Mechanism `cmd:",primary"`
	IV         []byte
}

func (c Cbc) Name() string {
	return c.Underlying.Name() + "-cbc"
}

func (c Cbc) BlockCipherUnderlying() Mechanism {
	return c.Underlying
}

func (c Cbc) BlockCipherIV() []byte {
	return c.IV
}
