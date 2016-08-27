package cryptokit

type Ecb struct {
	Underlying Mechanism
	IV []byte
}

func (c Ecb) Name() string {
	return c.Underlying.Name() + "-ebc"
}

func (c Ecb) BlockCipherUnderlying() Mechanism {
	return c.Underlying
}

func (c Ecb) BlockCipherIV() []byte {
	return c.IV
}
