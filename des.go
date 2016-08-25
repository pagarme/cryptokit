package cryptokit

type DesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *DesMechanism) BlockCipherMode() BlockCipherMode {
	return m.Mode
}

func (m *DesMechanism) BlockIV() []byte {
	return m.IV
}

func (m *DesMechanism) Name() string {
	return "des"
}
