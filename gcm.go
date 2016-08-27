package cryptokit

type GcmMechanism struct {
	Underlying Mechanism
	Nonce []byte
	AdditionalData []byte
}

func (c *GcmMechanism) Name() string {
	return c.Underlying.Name() + "-gcm"
}
