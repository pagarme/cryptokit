package cryptokit

type DesMechanism struct {
	Mode BlockCipherMode
	IV []byte
}

func (m *DesMechanism) Name() string {
	return "des"
}
