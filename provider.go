package cryptokit

import (
	"errors"
	"net/url"
)

type ProviderFactory func(*url.URL) (Provider, error)

type Provider interface {
	OpenSession() (Session, error)
	Close() error
}

var providers = map[string]ProviderFactory{}

func RegisterProvider(name string, factory ProviderFactory) {
	providers[name] = factory
}

func Create(uri string) (Provider, error) {
	providerUri, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	name := providerUri.Scheme

	factory, ok := providers[name]

	if !ok {
		return nil, errors.New("provider not found")
	}

	return factory(providerUri)
}
