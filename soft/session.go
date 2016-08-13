package soft

import (
	"errors"
	"crypto/rand"
	"encoding/json"
	"github.com/boltdb/bolt"
	"github.com/pagarme/cryptokit"
)

type Session struct {
	db *bolt.DB
}

func (s *Session) FindKey(id string) (cryptokit.Key, bool, error) {
	var bytes []byte

	err := s.db.View(func (tx *bolt.Tx) error {
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

	attribs := make(map[string]interface{})

	if err := json.Unmarshal(bytes, &attribs); err != nil {
		return nil, true, err
	}

	return loadKey(s, attribs), true, nil
}

func (s *Session) Encrypt(mech cryptokit.Mechanism, key cryptokit.Key, in []byte) ([]byte, error) {
	return nil, nil
}

func (s *Session) Decrypt(mech cryptokit.Mechanism, key cryptokit.Key, in []byte) ([]byte, error) {
	return nil, nil
}

func (s *Session) Translate(mech cryptokit.Mechanism, inKey cryptokit.Key, in []byte, outKey cryptokit.Key) ([]byte, error) {
	return nil, nil
}

func (s *Session) Wrap(mech cryptokit.Mechanism, key, kek cryptokit.Key) ([]byte, error) {
	return nil, nil
}

func (s *Session) Unwrap(mech cryptokit.Mechanism, key []byte, kek cryptokit.Key) (cryptokit.Key, error) {
	return nil, nil
}

func (s *Session) Generate(mech cryptokit.Mechanism, attributes cryptokit.KeyAttributes) (cryptokit.Key, error) {
	if err := s.checkConsistency(attributes); err != nil {
		return nil, err
	}

	data := make([]byte, attributes.Length)

	switch mech.(type) {
	case *cryptokit.RandomMechanism:
		_, err := rand.Read(data)

		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unsupported mechanism")
	}

	return s.createKey(attributes, data)
}

func (s *Session) Derive(mech cryptokit.Mechanism, key cryptokit.Key, attributes cryptokit.KeyAttributes) (cryptokit.Key, error) {
	return nil, nil
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
