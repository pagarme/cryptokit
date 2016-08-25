package cryptokit

type Session interface {
	FindKey(id string) (Key, bool, error)

	Encrypt(mech Mechanism, key Key, in []byte) ([]byte, error)
	Decrypt(mech Mechanism, key Key, in []byte) ([]byte, error)
	Translate(mech Mechanism, inKey Key, in []byte, outKey Key) ([]byte, error)

	Wrap(mech Mechanism, key, kek Key) ([]byte, error)
	Unwrap(mech Mechanism, key []byte, kek Key, attributes KeyAttributes) (Key, error)

	Generate(mech Mechanism, attributes KeyAttributes) (Key, error)
	Derive(mech Mechanism, key Key, attributes KeyAttributes) (Key, error)

	Close() error
}
