package cryptokit

type Dukpt struct {
	Ksn []byte
}

func (m Dukpt) Name() string {
	return "dukpt"
}
