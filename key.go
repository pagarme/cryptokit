package cryptokit

type KeyType uint
const (
	_ KeyType = iota
	AesKey
	DesKey
	TdesKey
	RsaKey
	DsaKey
)

type KeyCapability uint
const (
	_ KeyCapability = 0
	Encrypt = 0x1
	Decrypt = 0x2
	Wrap = 0x4
	Unwrap = 0x8
	Derive = 0x10

	EncryptDecrypt = Encrypt | Decrypt
	AllCapabilities = Encrypt | Decrypt | Wrap | Unwrap | Derive
)

type KeyAttributes struct {
	ID string
	Type KeyType
	Length uint
	Permanent bool
	Extractable bool
	Capabilities KeyCapability
}

type Key interface{
	ID() string
	Type() KeyType
	Length() uint
	Attributes() KeyAttributes

	Session() Session
	Destroy() error
	Close() error
}
