package soft

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"errors"

	"github.com/pagarme/cryptokit"
)

func processAead(mech cryptokit.Gcm, key cryptokit.Key, in []byte, encrypt bool) ([]byte, error) {
	impl, err := getImplementation(mech.Underlying, key)

	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(impl)

	if err != nil {
		return nil, err
	}

	if encrypt {
		return aead.Seal(nil, mech.Nonce, in, mech.AdditionalData), nil
	}

	return aead.Open(nil, mech.Nonce, in, mech.AdditionalData)
}

func processBlockCipher(mech cryptokit.BlockCipher, key cryptokit.Key, in []byte, encrypt bool) ([]byte, error) {
	impl, err := getImplementation(mech.BlockCipherUnderlying(), key)

	if err != nil {
		return nil, err
	}

	c, err := getBlockImplementation(mech, impl, encrypt)

	if err != nil {
		return nil, err
	}

	if len(in)%c.BlockSize() != 0 {
		return nil, errors.New("Input must be a multiple of block size")
	}

	out := make([]byte, len(in))

	c.CryptBlocks(out, in)

	return out, nil
}

func processHmac(mech cryptokit.Hmac, key cryptokit.Key, in []byte, encrypt bool) ([]byte, error) {
	skey := key.(*Key)

	if !encrypt {
		return nil, errors.New("This mechanism is encrypt only")
	}

	impl, err := getHashImplementation(mech.Underlying)

	if err != nil {
		return nil, err
	}

	h := hmac.New(impl.New, skey.data)
	_, _ = h.Write(in)

	return h.Sum(nil), nil
}

func getHashImplementation(mech cryptokit.Mechanism) (crypto.Hash, error) {
	switch mech.(type) {
	case cryptokit.Sha1:
		return crypto.SHA1, nil
	case cryptokit.Sha256:
		return crypto.SHA256, nil
	case cryptokit.Sha512:
		return crypto.SHA512, nil
	}

	return 0, errors.New("Unknown mechanism")
}

func getImplementation(mech cryptokit.Mechanism, key cryptokit.Key) (cipher.Block, error) {
	skey := key.(*Key)

	switch mech.(type) {
	case cryptokit.Aes:
		return aes.NewCipher(skey.data)
	case cryptokit.Des:
		return des.NewCipher(skey.data)
	case cryptokit.Tdes:
		return des.NewTripleDESCipher(skey.data)
	}

	return nil, errors.New("Unknown mechanism")
}

func getBlockImplementation(mech cryptokit.BlockCipher, impl cipher.Block, encrypt bool) (cipher.BlockMode, error) {
	var c cipher.BlockMode

	iv := mech.BlockCipherIV()

	if iv == nil {
		iv = make([]byte, impl.BlockSize())
	}

	switch mech.(type) {
	case cryptokit.Cbc:
		if encrypt {
			c = cipher.NewCBCEncrypter(impl, iv)
		} else {
			c = cipher.NewCBCDecrypter(impl, iv)
		}
	case cryptokit.Ecb:
		c = &ecbBlockMode{impl, encrypt}
	default:
		return nil, errors.New("Unknown block cipher mode")
	}

	return c, nil
}
