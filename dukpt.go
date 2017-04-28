package cryptokit

type Dukpt struct {
	Ksn []byte `cmd:",primary"`
}

func (m Dukpt) Name() string {
	return "dukpt"
}
