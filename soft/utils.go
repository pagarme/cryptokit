package soft

import (
	"errors"
	"crypto/aes"
	"crypto/des"
	"crypto/cipher"
	"github.com/pagarme/cryptokit"
)

func processBlockCipher(mech cryptokit.BlockCipher, key cryptokit.Key, in []byte, encrypt bool) ([]byte, error) {
	impl, err := getImplementation(mech, key)

	if err != nil {
		return nil, err
	}

	c, err := getBlockImplementation(mech, impl, encrypt)

	if err != nil {
		return nil, err
	}

	if len(in) % c.BlockSize() != 0 {
		return nil, errors.New("Input must be a multiple of block size")
	}

	out := make([]byte, len(in))

	c.CryptBlocks(out, in)

	return out, nil
}

func getImplementation(mech cryptokit.BlockCipher, key cryptokit.Key) (cipher.Block, error) {
	skey := key.(*Key)

	switch mech.(type) {
	case *cryptokit.AesMechanism:
		return aes.NewCipher(skey.data)
	case *cryptokit.DesMechanism:
		return des.NewCipher(skey.data)
	}

	return nil, errors.New("Unknown mechanism")
}

func getBlockImplementation(mech cryptokit.BlockCipher, impl cipher.Block, encrypt bool) (cipher.BlockMode, error) {
	var c cipher.BlockMode

	iv := mech.BlockIV()

	if iv == nil {
		iv = make([]byte, impl.BlockSize())
	}

	switch mech.BlockCipherMode() {
	case cryptokit.CBC:
		if encrypt {
			c = cipher.NewCBCEncrypter(impl, iv)
		} else {
			c = cipher.NewCBCDecrypter(impl, iv)
		}
	case cryptokit.ECB:
		c = &ecbBlockMode{impl, encrypt}
	default:
		return nil, errors.New("Unknown block cipher mode")
	}

	return c, nil
}
