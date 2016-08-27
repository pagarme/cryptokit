package cryptokit

type BlockCipher interface {
	BlockCipherUnderlying() Mechanism
	BlockCipherIV() []byte
}
