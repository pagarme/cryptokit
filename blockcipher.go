package cryptokit

type BlockCipher interface {
	BlockCipherMode() BlockCipherMode
	BlockIV() []byte
}
