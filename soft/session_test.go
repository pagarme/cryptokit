package soft

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/pagarme/cryptokit"
	"github.com/stretchr/testify/assert"
)

var wrongKey = []byte{1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 95, 16, 17, 18, 19, 255, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

func TestWrongMasterKey(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db", testKey)
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil provider was returned")

	s, err := p.OpenSession()
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil session was returned")

	key, err := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	assert.Nil(t, err, "An error ocurred generating the key")
	assert.NotNil(t, key, "A nil key was returned")

	err = s.Close()
	assert.Nil(t, err, "An error ocurred when closing the session")

	err = p.Close()
	assert.Nil(t, err, "An error ocurred when closing the provider")

	// Open again, with the wrong key
	p, err = New("testdb.db", wrongKey)
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil provider was returned")

	s, err = p.OpenSession()
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil session was returned")

	key2, found, err := s.FindKey("TestKeyGeneration")

	assert.NotNil(t, err, "An error didn't occur while finding the key")
	assert.Nil(t, key2, "A nil key wasn't returned")
	assert.False(t, found, "The key wasn found")

	err = s.Close()
	assert.Nil(t, err, "An error ocurred when closing the session")

	err = p.Close()
	assert.Nil(t, err, "An error ocurred when closing the provider")
}

func TestKeyGenerationAndLifetime(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db", testKey)
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil provider was returned")

	s, err := p.OpenSession()
	assert.Nil(t, err, "New returned an error")
	assert.NotNil(t, p, "A nil session was returned")

	key, err := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
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

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ciphertext, err := s.Encrypt(cryptokit.Ecb{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(cryptokit.Ecb{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestAesEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ciphertext, err := s.Encrypt(cryptokit.Cbc{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(cryptokit.Cbc{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestGcmEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ciphertext, err := s.Encrypt(cryptokit.Gcm{
		Underlying:     cryptokit.Aes{},
		Nonce:          []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		AdditionalData: nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(cryptokit.Gcm{
		Underlying:     cryptokit.Aes{},
		Nonce:          []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		AdditionalData: nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestDesEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.DesKey,
		Length:       8,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	ciphertext, err := s.Encrypt(cryptokit.Cbc{
		Underlying: cryptokit.Des{},
		IV:         nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(cryptokit.Cbc{
		Underlying: cryptokit.Des{},
		IV:         nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestTdesEncryptionDecryption(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.TdesKey,
		Length:       24,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	ciphertext, err := s.Encrypt(cryptokit.Cbc{
		Underlying: cryptokit.Tdes{},
		IV:         nil,
	}, key, plaintext)

	assert.Nil(t, err, "An error during encryption")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, plaintext, "Plaintext must be different from ciphertext")

	plaintext2, err := s.Decrypt(cryptokit.Cbc{
		Underlying: cryptokit.Tdes{},
		IV:         nil,
	}, key, ciphertext)

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil plaintext was returned")
	assert.Equal(t, plaintext, plaintext2, "Plaintext must be equal to original plaintext")
}

func TestSha1(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	plaintext := []byte("lol")

	ciphertext, err := s.Hash(cryptokit.Sha1{}, plaintext)

	assert.Nil(t, err, "An error during hashing")
	assert.NotNil(t, ciphertext, "A nil hash was returned")
	assert.Equal(t, "403926033d001b5279df37cbbe5287b7c7c267fa", hex.EncodeToString(ciphertext))
}

func TestSha256(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	plaintext := []byte("lol")

	ciphertext, err := s.Hash(cryptokit.Sha256{}, plaintext)

	assert.Nil(t, err, "An error during hashing")
	assert.NotNil(t, ciphertext, "A nil hash was returned")
	assert.Equal(t, "07123e1f482356c415f684407a3b8723e10b2cbbc0b8fcd6282c49d37c9c1abc", hex.EncodeToString(ciphertext))
}

func TestSha512(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	plaintext := []byte("lol")

	ciphertext, err := s.Hash(cryptokit.Sha512{}, plaintext)

	assert.Nil(t, err, "An error during hashing")
	assert.NotNil(t, ciphertext, "A nil hash was returned")
	assert.Equal(t, "3dd28c5a23f780659d83dd99981e2dcb82bd4c4bdc8d97a7da50ae84c7a7229a6dc0ae8ae4748640a4cc07ccc2d55dbdc023a99b3ef72bc6ce49e30b84253dae", hex.EncodeToString(ciphertext))
}

func TestHmac(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.FixedKey{
		Key: []byte("test"),
	}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.RawKey,
		Length:       4,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	plaintext := []byte("lol")

	ciphertext, err := s.Encrypt(cryptokit.Hmac{
		Underlying: cryptokit.Sha1{},
	}, key, plaintext)

	assert.Nil(t, err, "An error during hashing")
	assert.NotNil(t, ciphertext, "A nil hash was returned")
	assert.Equal(t, "e68dfbf5296ca87f442782b1649ddc3ffcfbee7b", hex.EncodeToString(ciphertext))
}

func TestWrapUnwrap(t *testing.T) {
	defer os.Remove("testdb.db")

	p, _ := New("testdb.db", testKey)
	s, _ := p.OpenSession()

	defer p.Close()
	defer s.Close()

	key, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  true,
		Capabilities: cryptokit.AllCapabilities,
	})

	keyData, _ := key.Extract()

	wrapping, _ := s.Generate(cryptokit.Random{}, cryptokit.KeyAttributes{
		ID:           "WrappingKey",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    true,
		Extractable:  false,
		Capabilities: cryptokit.AllCapabilities,
	})

	ciphertext, err := s.Wrap(cryptokit.Cbc{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, wrapping, key)

	assert.Nil(t, err, "An error during Wrapping")
	assert.NotNil(t, ciphertext, "A nil ciphertext was returned")
	assert.NotEqual(t, ciphertext, keyData, "Plaintext must be different from ciphertext")

	key2, err := s.Unwrap(cryptokit.Cbc{
		Underlying: cryptokit.Aes{},
		IV:         nil,
	}, wrapping, ciphertext, cryptokit.KeyAttributes{
		ID:           "TestKeyGeneration2",
		Type:         cryptokit.AesKey,
		Length:       32,
		Permanent:    false,
		Extractable:  true,
		Capabilities: cryptokit.AllCapabilities,
	})

	assert.Nil(t, err, "An error during decryption")
	assert.NotNil(t, ciphertext, "A nil key was returned")

	keyData2, _ := key2.Extract()

	assert.Equal(t, keyData, keyData2, "Plaintext must be equal to original plaintext")
}
