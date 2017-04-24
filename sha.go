package cryptokit

type Sha1 struct {
}

func (m Sha1) Name() string {
	return "sha1"
}

type Sha256 struct {
}

func (m Sha256) Name() string {
	return "sha256"
}

type Sha512 struct {
}

func (m Sha512) Name() string {
	return "sha512"
}
