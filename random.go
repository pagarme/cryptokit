package cryptokit

type RandomMechanism struct {
}

func (m *RandomMechanism) Name() string {
	return "random"
}

