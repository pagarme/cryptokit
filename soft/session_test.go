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

	assert.Nil(t, err, "An error ocurred finding the key")
	assert.NotNil(t, key2, "A nil key was returned")
	assert.True(t, found, "The key wasn't found")

	assert.Equal(t, key.ID(), key2.ID())

	err = key2.Destroy()
	assert.Nil(t, err, "An error ocurred destroying the key")

	key3, found, err := s.FindKey("TestKeyGeneration")

	assert.Nil(t, err, "An error ocurred finding the key")
	assert.Nil(t, key3, "A nil key was returned")
	assert.False(t, found, "The key wasn't destroyed")

	err = s.Close()
	assert.Nil(t, err, "An error ocurred when closing the session")

	err = p.Close()
	assert.Nil(t, err, "An error ocurred when closing the provider")
}

func TestEcbEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db")
	s, err := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, err := s.Generate(&cryptokit.RandomMechanism{}, cryptokit.KeyAttributes{
		ID: "TestKeyGeneration",
		Type: cryptokit.Aes,
		Length: 32,
		Permanent: true,
		Extractable: false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

	ciphertext, err := s.Encrypt(&cryptokit.AesMechanism{
		cryptokit.ECB,
		nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(&cryptokit.AesMechanism{
		cryptokit.ECB,
		nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestAesEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db")
	s, err := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, err := s.Generate(&cryptokit.RandomMechanism{}, cryptokit.KeyAttributes{
		ID: "TestKeyGeneration",
		Type: cryptokit.Aes,
		Length: 32,
		Permanent: true,
		Extractable: false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

	ciphertext, err := s.Encrypt(&cryptokit.AesMechanism{
		cryptokit.CBC,
		nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(&cryptokit.AesMechanism{
		cryptokit.CBC,
		nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestDesEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db")
	s, err := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, err := s.Generate(&cryptokit.RandomMechanism{}, cryptokit.KeyAttributes{
		ID: "TestKeyGeneration",
		Type: cryptokit.Des,
		Length: 8,
		Permanent: true,
		Extractable: false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0,0,0,0,0,0,0,0}

	ciphertext, err := s.Encrypt(&cryptokit.DesMechanism{
		cryptokit.CBC,
		nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(&cryptokit.DesMechanism{
		cryptokit.CBC,
		nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}
