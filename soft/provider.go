package soft

import (
	"github.com/boltdb/bolt"
	"github.com/pagarme/cryptokit"
)

type Provider struct {
	db *bolt.DB
}

func New(path string) (*Provider, error) {
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

	return &Provider{db}, nil
}

func (p *Provider) OpenSession() (cryptokit.Session, error) {
	return &Session{p.db}, nil
}

func (p *Provider) Close() error {
	return p.db.Close()
}
