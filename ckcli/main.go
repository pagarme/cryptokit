package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/docopt/docopt.go"
	"github.com/pagarme/cryptokit"

	_ "github.com/pagarme/cryptokit/soft"
)

type findKeyArgs struct {
	ID string `cmd:",primary"`
}

type encryptArgs struct {
	Mech cryptokit.Mechanism `cmd:",primary"`
	Key  cryptokit.Key
	In   []byte
	Out  io.Writer
}

type translateArgs struct {
	Mech   cryptokit.Mechanism `cmd:",primary"`
	InKey  cryptokit.Key
	In     []byte
	OutKey cryptokit.Key
	Out    io.Writer
}

type wrapArgs struct {
	Mech cryptokit.Mechanism `cmd:",primary"`
	Kek  cryptokit.Key
	Key  cryptokit.Key
}

type keyAttributesArgs struct {
	In           []byte
	ID           string
	Type         cryptokit.KeyType
	Length       uint
	Permanent    bool
	Extractable  bool
	Capabilities []cryptokit.KeyCapability `cmd:"cap"`
}

func (a *keyAttributesArgs) BuildAttributes() cryptokit.KeyAttributes {
	var caps cryptokit.KeyCapability

	for _, c := range a.Capabilities {
		caps = caps | c
	}

	if caps == 0 {
		caps = cryptokit.AllCapabilities
	}

	attrs := cryptokit.KeyAttributes{
		ID:           a.ID,
		Type:         a.Type,
		Length:       a.Length,
		Permanent:    a.Permanent,
		Extractable:  a.Extractable,
		Capabilities: caps,
	}

	return attrs
}

type unwrapArgs struct {
	keyAttributesArgs

	Mech cryptokit.Mechanism `cmd:",primary"`
	Kek  cryptokit.Key
}

type generateArgs struct {
	keyAttributesArgs

	Mech cryptokit.Mechanism `cmd:",primary"`
}

type deriveArgs struct {
	keyAttributesArgs

	Mech cryptokit.Mechanism `cmd:",primary"`
	Key  cryptokit.Key
}

type hashArgs struct {
	Mech cryptokit.Mechanism `cmd:",primary"`
	In   []byte
	Out  io.Writer
}

var session cryptokit.Session

func findKey(a *findKeyArgs) (cryptokit.Key, error) {
	k, ok, err := session.FindKey(a.ID)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("key not found")
	}

	return k, nil
}

func hash(a *hashArgs) ([]byte, error) {
	result, err := session.Hash(a.Mech, a.In)

	if err != nil {
		return nil, err
	}

	if a.Out == nil {
		return result, nil
	}

	_, err = a.Out.Write(result)

	return nil, err
}

func encrypt(a *encryptArgs) ([]byte, error) {
	result, err := session.Encrypt(a.Mech, a.Key, a.In)

	if err != nil {
		return nil, err
	}

	if a.Out == nil {
		return result, nil
	}

	_, err = a.Out.Write(result)

	return nil, err
}

func decrypt(a *encryptArgs) ([]byte, error) {
	result, err := session.Decrypt(a.Mech, a.Key, a.In)

	if err != nil {
		return nil, err
	}

	if a.Out == nil {
		return result, nil
	}

	_, err = a.Out.Write(result)

	return nil, err
}

func translate(a *translateArgs) ([]byte, error) {
	result, err := session.Translate(a.Mech, a.InKey, a.In, a.OutKey)

	if err != nil {
		return nil, err
	}

	if a.Out == nil {
		return result, nil
	}

	_, err = a.Out.Write(result)

	return nil, err
}

func generate(a *generateArgs) (cryptokit.Key, error) {
	return session.Generate(a.Mech, a.BuildAttributes())
}

func wrap(a *wrapArgs) ([]byte, error) {
	return session.Wrap(a.Mech, a.Kek, a.Key)
}

func unwrap(a *unwrapArgs) (cryptokit.Key, error) {
	return session.Unwrap(a.Mech, a.Kek, a.In, a.BuildAttributes())
}

func derive(a *deriveArgs) (cryptokit.Key, error) {
	return session.Derive(a.Mech, a.Key, a.BuildAttributes())
}

func init() {
	RegisterCommand("generate", generate)
	RegisterCommand("find", findKey)
	RegisterCommand("hash", hash)
	RegisterCommand("encrypt", encrypt)
	RegisterCommand("decrypt", decrypt)
	RegisterCommand("wrap", wrap)
	RegisterCommand("unwrap", unwrap)
}

func main() {
	usage := `Cryptokit CLI
	
Usage:
	ckcli <url>
	
Options:
	-h --help	Show this text.
	--version	Show version.`

	args, err := docopt.Parse(usage, nil, true, "Cryptokit", false)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
		return
	}

	url, ok := args["<url>"]

	if !ok {
		fmt.Println(usage)
		os.Exit(1)
		return
	}

	p, err := cryptokit.Create(url.(string))

	if err != nil {
		fmt.Printf("Error creating provider: %s\n", err)
		os.Exit(1)
		return
	}

	session, err = p.OpenSession()

	if err != nil {
		fmt.Printf("Error opening session: %s\n", err)
		os.Exit(1)
		return
	}

	defer session.Close()
	defer p.Close()

	err = runRepl()

	if err != nil {
		fmt.Printf("Error running repl: %s\n", err)
		os.Exit(1)
		return
	}

	os.Exit(0)
}
