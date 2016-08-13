package cryptokit

type RandomMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *RandomMechanism) Name() string {
	return "random"
}

