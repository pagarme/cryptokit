package cryptokit

type FixedKey struct {
	Key []byte `cmd:",primary"`
}

func (m FixedKey) Name() string {
	return "fixedkey"
}
