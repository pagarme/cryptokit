package cryptokit

type Session interface {
	FindKey(id string) (Key, bool, error)

	Encrypt(mech Mechanism, key Key, in []byte) ([]byte, error)
	Decrypt(mech Mechanism, key Key, in []byte) ([]byte, error)
	Translate(mech Mechanism, inKey Key, in []byte, outKey Key) ([]byte, error)

	Wrap(mech Mechanism, kek, key Key) ([]byte, error)
	Unwrap(mech Mechanism, kek Key, key []byte, attributes KeyAttributes) (Key, error)

	Generate(mech Mechanism, attributes KeyAttributes) (Key, error)
	Derive(mech Mechanism, key Key, attributes KeyAttributes) (Key, error)

	Close() error
}
