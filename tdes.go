package cryptokit

type TDesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *TDesMechanism) BlockCipherMode() BlockCipherMode {
	return m.Mode
}

func (m *TDesMechanism) BlockIV() []byte {
	return m.IV
}

func (m *TDesMechanism) Name() string {
	return "tdes"
}
