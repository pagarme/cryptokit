package cryptokit

type KeyType uint

const (
	_       KeyType = 0
	AesKey          = 1
	DesKey          = 2
	TdesKey         = 3
	RsaKey          = 3
	DsaKey          = 4
	RawKey          = 5
)

type KeyCapability uint

const (
	_       KeyCapability = 0
	Encrypt               = 0x1
	Decrypt               = 0x2
	Wrap                  = 0x4
	Unwrap                = 0x8
	Derive                = 0x10

	EncryptDecrypt  = Encrypt | Decrypt
	AllCapabilities = Encrypt | Decrypt | Wrap | Unwrap | Derive
)

type KeyAttributes struct {
	ID           string
	Type         KeyType
	Length       uint
	Permanent    bool
	Extractable  bool
	Capabilities KeyCapability
}

type Key interface {
	ID() string
	Type() KeyType
	Length() uint
	Attributes() KeyAttributes
	Extract() ([]byte, error)

	Session() Session
	Destroy() error
	Close() error
}
