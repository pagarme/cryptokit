package soft

import (
	"encoding/base64"
	"errors"
	"github.com/pagarme/cryptokit"
)

type Key struct {
	id           string
	typ          cryptokit.KeyType
	length       uint
	permanent    bool
	extractable  bool
	capabilities cryptokit.KeyCapability
	session      *Session
	data         []byte
}

func newKey(s *Session, a cryptokit.KeyAttributes, data []byte) *Key {
	return &Key{
		id:           a.ID,
		typ:          a.Type,
		length:       a.Length,
		extractable:  a.Extractable,
		permanent:    a.Permanent,
		capabilities: a.Capabilities,
		session:      s,
		data:         data,
	}
}

func loadKey(s *Session, a map[string]interface{}) *Key {
	data, _ := base64.StdEncoding.DecodeString(a["data"].(string))

	return &Key{
		id:           a["id"].(string),
		typ:          cryptokit.KeyType(a["type"].(float64)),
		length:       uint(a["length"].(float64)),
		extractable:  a["extractable"].(bool),
		permanent:    a["permanent"].(bool),
		capabilities: cryptokit.KeyCapability(a["capabilities"].(float64)),
		session:      s,
		data:         data,
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
		ID:           k.id,
		Type:         k.typ,
		Length:       k.length,
		Permanent:    k.permanent,
		Extractable:  k.extractable,
		Capabilities: k.capabilities,
	}
}

func (k *Key) Session() cryptokit.Session {
	return k.session
}

func (k *Key) Extract() ([]byte, error) {
	if !k.extractable {
		return nil, errors.New("Key is not extractable")
	}

	return k.data, nil
}

func (k *Key) Destroy() error {
	if k.permanent {
		return k.session.db.Remove(k.id)
	}

	return k.Close()
}

func (k *Key) Close() error {
	return nil
}

func (k *Key) save() error {
	attributes := map[string]interface{}{
		"id":           k.id,
		"type":         k.typ,
		"length":       k.length,
		"extractable":  k.extractable,
		"permanent":    k.permanent,
		"capabilities": k.capabilities,
		"data":         base64.StdEncoding.EncodeToString(k.data),
	}

	err := k.session.db.Save(k.id, attributes)

	if err != nil {
		return err
	}

	k.permanent = true

	return nil
}
