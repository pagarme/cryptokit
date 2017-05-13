package soft

import (
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path"

	"github.com/pagarme/cryptokit"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

type Provider struct {
	db Database
}

func createSoft(u *url.URL) (cryptokit.Provider, error) {
	query := u.Query()

	keyString, ok := query["key"]

	if !ok {
		return nil, errors.New("missing key")
	}

	key, err := hex.DecodeString(keyString[0])

	if err != nil {
		return nil, err
	}

	p, err := New(path.Join(u.Host, u.Path), key)

	if err != nil {
		return nil, err
	}

	return p, nil
}

func createSoftWithVaultHTTP(u *url.URL) (cryptokit.Provider, error) {
	return createSoftWithVault(u, false)
}

func createSoftWithVaultHTTPS(u *url.URL) (cryptokit.Provider, error) {
	return createSoftWithVault(u, true)
}

func createSoftWithVault(u *url.URL, https bool) (cryptokit.Provider, error) {
	vaultURL := &url.URL{
		Host: u.Host,
	}

	if https {
		vaultURL.Scheme = "https"
	} else {
		vaultURL.Scheme = "http"
	}

	query := u.Query()
	token, ok := query["token"]

	if !ok {

		token = append(token, os.Getenv("VAULT_TOKEN"))
		if len(token[0]) == 0 {
			return nil, errors.New("missing token, it may come from provider url query string parameter \"token\" or from VAULT_TOKEN environment variable")
		}
	}

	p, err := NewWithVault(vaultURL.String(), token[0], u.Path)

	if err != nil {
		return nil, err
	}

	return p, nil
}

func init() {
	cryptokit.RegisterProvider("soft", createSoft)
	cryptokit.RegisterProvider("soft+vault+http", createSoftWithVaultHTTP)
	cryptokit.RegisterProvider("soft+vault+https", createSoftWithVaultHTTPS)
}

func New(path string, key []byte) (*Provider, error) {
	return NewWithBolt(path, key)
}

func NewWithBolt(path string, key []byte) (*Provider, error) {
	db, err := newBoltDatabase(path, key)

	if err != nil {
		return nil, err
	}

	return NewWithDatabase(db)
}

func NewWithVault(address, token, base string) (*Provider, error) {
	db, err := newVaultDatabase(address, token, base)

	if err != nil {
		return nil, err
	}

	return NewWithDatabase(db)
}

func NewWithDatabase(db Database) (*Provider, error) {
	return &Provider{
		db: db,
	}, nil
}

func (p *Provider) OpenSession() (cryptokit.Session, error) {
	return &Session{db: p.db}, nil
}

func (p *Provider) Close() error {
	return p.db.Close()
}
