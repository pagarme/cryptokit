package cryptokit

type AesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *AesMechanism) BlockCipherMode() BlockCipherMode {
	return m.Mode
}

func (m *AesMechanism) BlockIV() []byte {
	return m.IV
}

func (m *AesMechanism) Name() string {
	return "aes"
}
