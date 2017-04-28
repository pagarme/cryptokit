package cryptokit

type Gcm struct {
	Underlying     Mechanism `cmd:",primary"`
	Nonce          []byte    `cmd:"nonce"`
	AdditionalData []byte    `cmd:"additional-data"`
}

func (c Gcm) Name() string {
	return c.Underlying.Name() + "-gcm"
}
