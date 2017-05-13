package soft

import (
	"encoding/json"
	"errors"
	"path"

	"github.com/hashicorp/vault/api"
)

type vaultDatabase struct {
	base  string
	vault *api.Client
}

func newVaultDatabase(address, token, base string) (*vaultDatabase, error) {
	config := &api.Config{
		Address: address,
	}

	vault, err := api.NewClient(config)

	if err != nil {
		return nil, err
	}

	vault.SetToken(token)

	return &vaultDatabase{
		base:  base,
		vault: vault,
	}, nil
}

func (b *vaultDatabase) ListKeys() ([]string, error) {
	s, err := b.vault.Logical().List(path.Join("secret", b.base))

	if err != nil {
		return nil, err
	}

	if s == nil {
		return []string{}, nil
	}

	keysI, found := s.Data["keys"]

	if !found {
		return nil, errors.New("error reading response from vault")
	}

	keysArr, ok := keysI.([]interface{})

	if !ok {
		return nil, errors.New("error reading response from vault")
	}

	keys := make([]string, len(keysArr))

	for i, v := range keysArr {
		str, ok := v.(string)

		if !ok {
			return nil, errors.New("error reading response from vault")
		}

		keys[i] = str
	}

	return keys, nil
}

func (b *vaultDatabase) FindKey(id string) (map[string]interface{}, bool, error) {
	result := map[string]interface{}{}

	s, err := b.vault.Logical().Read(path.Join("secret", b.base, id))

	if err != nil {
		return nil, false, err
	}

	if s == nil {
		return nil, false, nil
	}

	j, err := json.Marshal(s.Data)

	if err != nil {
		return nil, false, err
	}

	err = json.Unmarshal(j, &result)

	if err != nil {
		return nil, false, err
	}

	return result, true, nil
}

func (b *vaultDatabase) Save(id string, attributes map[string]interface{}) error {
	_, err := b.vault.Logical().Write(path.Join("secret", b.base, id), attributes)

	return err
}

func (b *vaultDatabase) Remove(id string) error {
	_, err := b.vault.Logical().Delete(path.Join("secret", b.base, id))

	return err
}

func (b *vaultDatabase) Close() error {
	return nil
}
