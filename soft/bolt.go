package soft

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"

	"github.com/boltdb/bolt"
)

type boltDatabase struct {
	db        *bolt.DB
	masterKey cipher.Block
}

func newBoltDatabase(path string, key []byte) (*boltDatabase, error) {
	db, err := bolt.Open(path, 0600, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte("keys"))
		return err
	})

	if err != nil {
		return nil, err
	}

	masterKey, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	return &boltDatabase{
		db:        db,
		masterKey: masterKey,
	}, nil
}

func (b *boltDatabase) Save(id string, attributes map[string]interface{}) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte("keys"))

		bytes, err := json.Marshal(attributes)

		if err != nil {
			return err
		}

		ciphertext, err := b.encryptStore(bytes)

		if err != nil {
			return err
		}

		if err := bkt.Put([]byte(id), ciphertext); err != nil {
			return err
		}

		return nil
	})
}

func (b *boltDatabase) ListKeys() ([]string, error) {
	var keys []string

	err := b.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))

		_ = b.ForEach(func(k, _ []byte) error {
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

func (b *boltDatabase) FindKey(id string) (map[string]interface{}, bool, error) {
	var bytes []byte

	err := b.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))

		bytes = b.Get([]byte(id))

		return nil
	})

	if err != nil {
		return nil, false, err
	}

	if len(bytes) == 0 {
		return nil, false, nil
	}

	plaintext, err := b.decryptStore(bytes)

	if err != nil {
		return nil, false, err
	}

	attribs := make(map[string]interface{})

	if err := json.Unmarshal(plaintext, &attribs); err != nil {
		return nil, true, err
	}

	return attribs, true, nil
}

func (b *boltDatabase) Remove(id string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte("keys"))

		return bkt.Delete([]byte(id))
	})
}

func (b *boltDatabase) Close() error {
	return b.db.Close()
}

func (b *boltDatabase) encryptStore(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(b.masterKey)

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

func (b *boltDatabase) decryptStore(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(b.masterKey)

	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)

	return plaintext, err
}
