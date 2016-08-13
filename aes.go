package cryptokit

type AesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *AesMechanism) Name() string {
	return "aes"
}
