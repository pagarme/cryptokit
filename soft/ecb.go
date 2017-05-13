package soft

import (
	"crypto/cipher"
)

type ecbBlockMode struct {
	impl    cipher.Block
	encrypt bool
}

func (e *ecbBlockMode) BlockSize() int {
	return e.impl.BlockSize()
}

func (e *ecbBlockMode) CryptBlocks(dst, src []byte) {
	bs := e.BlockSize()

	for i := 0; i < len(src); i += bs {
		if e.encrypt {
			e.impl.Encrypt(dst[i:i+bs], src[i:i+bs])
		} else {
			e.impl.Decrypt(dst[i:i+bs], src[i:i+bs])
		}
	}
}
