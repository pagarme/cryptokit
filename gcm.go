package cryptokit

type Gcm struct {
	Underlying Mechanism
	Nonce []byte
	AdditionalData []byte
}

func (c Gcm) Name() string {
	return c.Underlying.Name() + "-gcm"
}
