package cryptokit

type BlockCipherMode uint
const (
	_ BlockCipherMode = iota
	ECB
	CBC
	OFB
	PCBC
	CFB
	CTR
	GCM
)
