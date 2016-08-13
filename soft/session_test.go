package soft

import (
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/pagarme/cryptokit"
)

func TestKeyGeneration(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db")
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil provider was returned")

	s, err := p.OpenSession()
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil session was returned")

	key, err := s.Generate(&cryptokit.RandomMechanism{}, cryptokit.KeyAttributes{
		ID: "TestKeyGeneration",
		Type: cryptokit.Aes,
		Length: 32,
		Permanent: true,
		Extractable: false,
		Capabilities: cryptokit.AllCapabilities,
	})

	assert.Nil(t, err, "An error ocurred generating the key")
	assert.NotNil(t, key, "A nil key was returned")

	key2, found, err := s.FindKey("TestKeyGeneration")

	assert.Nil(t, err, "An error ocurred generating the key")
	assert.NotNil(t, key2, "A nil key was returned")
	assert.True(t, found, "The key wasn't found")

	assert.Equal(t, key.ID(), key2.ID())

	err = s.Close()
	assert.Nil(t, err, "An error ocurred when closing the session")

	err = p.Close()
	assert.Nil(t, err, "An error ocurred when closing the provider")
}
