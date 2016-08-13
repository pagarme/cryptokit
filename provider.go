package cryptokit

type Provider interface {
	OpenSession() (Session, error)
	Close() error
}
