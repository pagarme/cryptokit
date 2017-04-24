package cryptokit

type FixedKey struct {
	Key []byte
}

func (m FixedKey) Name() string {
	return "fixedkey"
}
