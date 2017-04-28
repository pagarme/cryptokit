package soft

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/boltdb/bolt"
	"github.com/pagarme/cryptokit"
	"github.com/pagarme/cryptokit/soft/dukpt"
)

type Session struct {
	db        *bolt.DB
	masterKey cipher.Block
}

func (s *Session) ListKeys() ([]string, error) {
	var keys []string

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))

		b.ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (s *Session) FindKey(id string) (cryptokit.Key, bool, error) {
	var bytes []byte

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))

		bytes = b.Get([]byte(id))

		return nil
	})

	if err != nil {
		return nil, false, err
	}

	if bytes == nil || len(bytes) == 0 {
		return nil, false, nil
	}

	plaintext, err := s.decryptStore(bytes)

	if err != nil {
		return nil, false, err
	}

	attribs := make(map[string]interface{})

	if err := json.Unmarshal(plaintext, &attribs); err != nil {
		return nil, true, err
	}

	return loadKey(s, attribs), true, nil
}

func (s *Session) Encrypt(mech cryptokit.Mechanism, key cryptokit.Key, in []byte) ([]byte, error) {
	if key.Attributes().Capabilities&cryptokit.Encrypt == 0 {
		return nil, errors.New("Key can't be used for encryption")
	}

	return s.encryptionCore(mech, key, in, true)
}

func (s *Session) Decrypt(mech cryptokit.Mechanism, key cryptokit.Key, in []byte) ([]byte, error) {
	if key.Attributes().Capabilities&cryptokit.Decrypt == 0 {
		return nil, errors.New("Key can't be used for decryption")
	}

	return s.encryptionCore(mech, key, in, false)
}

func (s *Session) Translate(mech cryptokit.Mechanism, inKey cryptokit.Key, in []byte, outKey cryptokit.Key) ([]byte, error) {
	data, err := s.Decrypt(mech, inKey, in)

	if err != nil {
		return nil, err
	}

	return s.Encrypt(mech, outKey, data)
}

func (s *Session) Wrap(mech cryptokit.Mechanism, kek, key cryptokit.Key) ([]byte, error) {
	if kek.Attributes().Capabilities&cryptokit.Wrap == 0 {
		return nil, errors.New("Key can't be used for wrapping")
	}

	return s.encryptionCore(mech, kek, key.(*Key).data, true)
}

func (s *Session) Unwrap(mech cryptokit.Mechanism, kek cryptokit.Key, key []byte, attributes cryptokit.KeyAttributes) (cryptokit.Key, error) {
	if kek.Attributes().Capabilities&cryptokit.Unwrap == 0 {
		return nil, errors.New("Key can't be used for unwrapping")
	}

	if err := s.checkConsistency(attributes); err != nil {
		return nil, err
	}

	data, err := s.encryptionCore(mech, kek, key, false)

	if err != nil {
		return nil, err
	}

	return s.createKey(attributes, data)
}

func (s *Session) Generate(mech cryptokit.Mechanism, attributes cryptokit.KeyAttributes) (cryptokit.Key, error) {
	if err := s.checkConsistency(attributes); err != nil {
		return nil, err
	}

	data := make([]byte, attributes.Length)

	switch v := mech.(type) {
	case cryptokit.FixedKey:
		copy(data, v.Key)
	case cryptokit.Random:
		if _, err := rand.Read(data); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unsupported mechanism")
	}

	return s.createKey(attributes, data)
}

func (s *Session) Derive(mech cryptokit.Mechanism, key cryptokit.Key, attributes cryptokit.KeyAttributes) (cryptokit.Key, error) {
	var data []byte

	if key.Attributes().Capabilities&cryptokit.Derive == 0 {
		return nil, errors.New("Key can't be used for derivation")
	}

	if err := s.checkConsistency(attributes); err != nil {
		return nil, err
	}

	skey := key.(*Key)

	switch v := mech.(type) {
	case cryptokit.Dukpt:
		d, err := dukpt.DerivePekFromBdk(skey.data, v.Ksn)

		if err != nil {
			return nil, err
		}

		data = d
	default:
		return nil, errors.New("Unsupported mechanism")
	}

	return s.createKey(attributes, data)
}

func (s *Session) Hash(mech cryptokit.Mechanism, in []byte) ([]byte, error) {
	hash, err := getHashImplementation(mech)

	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(in)

	return h.Sum(nil), nil
}

func (s *Session) Close() error {
	return nil
}

func (s *Session) checkConsistency(a cryptokit.KeyAttributes) error {
	if a.Length <= 0 {
		return errors.New("Invalid key size")
	}

	return nil
}

func (s *Session) createKey(a cryptokit.KeyAttributes, data []byte) (*Key, error) {
	k := newKey(s, a, data)

	if k.permanent {
		if err := k.save(); err != nil {
			return nil, err
		}
	}

	return k, nil
}

func (s *Session) encryptionCore(mech cryptokit.Mechanism, key cryptokit.Key, in []byte, encrypt bool) ([]byte, error) {
	switch v := mech.(type) {
	case cryptokit.BlockCipher:
		return processBlockCipher(v, key, in, encrypt)
	case cryptokit.Gcm:
		return processAead(v, key, in, encrypt)
	case cryptokit.Hmac:
		return processHmac(v, key, in, encrypt)
	}

	return nil, errors.New("Unknown mechanism")
}

func (s *Session) encryptStore(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.masterKey)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

func (s *Session) decryptStore(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.masterKey)

	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)

	return plaintext, err
}
