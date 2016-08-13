package cryptokit

type DukptMechanism struct {
	Ksn []byte
}

func (m *DukptMechanism) Name() string {
	return "dukpt"
}
