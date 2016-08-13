package soft

import (
	"encoding/json"
	"encoding/base64"
	"github.com/boltdb/bolt"
	"github.com/pagarme/cryptokit"
)

type Key struct {
	id string
	typ cryptokit.KeyType
	length uint
	permanent bool
	extractable bool
	capabilities cryptokit.KeyCapability
	session *Session
	data []byte
}

func newKey(s *Session, a cryptokit.KeyAttributes, data []byte) *Key {
	return &Key{
		id: a.ID,
		typ: a.Type,
		length: a.Length,
		extractable: a.Extractable,
		permanent: a.Permanent,
		capabilities: a.Capabilities,
		session: s,
		data: data,
	}
}

func loadKey(s *Session, a map[string]interface{}) *Key {
	data, _ := base64.StdEncoding.DecodeString(a["data"].(string))

	return &Key{
		id: a["id"].(string),
		typ: cryptokit.KeyType(a["type"].(float64)),
		length: uint(a["length"].(float64)),
		extractable: a["extractable"].(bool),
		permanent: a["permanent"].(bool),
		capabilities: cryptokit.KeyCapability(a["capabilities"].(float64)),
		session: s,
		data: data,
	}
}

func (k *Key) ID() string {
	return k.id
}

func (k *Key) Type() cryptokit.KeyType {
	return k.typ
}

func (k *Key) Length() uint {
	return k.length
}

func (k *Key) Attributes() cryptokit.KeyAttributes {
	return cryptokit.KeyAttributes{
		ID: k.id,
		Type: k.typ,
		Length: k.length,
		Permanent: k.permanent,
		Extractable: k.extractable,
		Capabilities: k.capabilities,
	}
}

func (k *Key) Session() cryptokit.Session {
	return k.session
}

func (k *Key) Destroy() error {
	if k.permanent {
		err := k.session.db.Update(func (tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))

			return b.Delete([]byte(k.id))
		})

		if err != nil {
			return err
		}
	}

	return k.Close()
}

func (k *Key) Close() error {
	return nil
}

func (k *Key) save() error {
	return k.session.db.Update(func (tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))

		attributes := map[string]interface{}{
			"id": k.id,
			"type": k.typ,
			"length": k.length,
			"extractable": k.extractable,
			"permanent": k.permanent,
			"capabilities": k.capabilities,
			"data": base64.StdEncoding.EncodeToString(k.data),
		}

		bytes, err := json.Marshal(attributes)

		if err != nil {
			return err
		}

		if err := b.Put([]byte(k.id), bytes); err != nil {
			return err
		}

		k.permanent = true

		return nil
	})
}
