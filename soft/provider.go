package soft

import (
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"github.com/boltdb/bolt"
	"github.com/pagarme/cryptokit"
)

type Provider struct {
	db *bolt.DB
	masterKey cipher.Block
}

func New(path string, key []byte) (*Provider, error) {
	db, err := bolt.Open(path, 0600, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func (tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte("keys")); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	masterKey, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	return &Provider{db, masterKey}, nil
}

func (p *Provider) OpenSession() (cryptokit.Session, error) {
	if p.masterKey == nil {
		return nil, errors.New("The master key isn't ready yet")
	}

	return &Session{p.db, p.masterKey}, nil
}

func (p *Provider) Close() error {
	p.masterKey = nil

	return p.db.Close()
}
