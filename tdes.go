package cryptokit

type TDesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *TDesMechanism) Name() string {
	return "tdes"
}
