package cryptokit

type Cbc struct {
	Underlying Mechanism
	IV []byte
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
