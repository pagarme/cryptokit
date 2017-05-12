package soft

import (
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
)

var testKey = []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31}

func TestProviderLifecycle(t *testing.T) {
	defer func() {
		_ = os.Remove("testdb.db")
	}()

	p, err := New("testdb.db", testKey)
	assert.Nil(t, err, "Should not return a error")
	assert.NotNil(t, p, "Should return an instance")

	s, err := p.OpenSession()
	assert.Nil(t, err, "Should not return a error")
	assert.NotNil(t, s, "Should return an instance")

	err = s.Close()
	assert.Nil(t, err, "Should not return a error when closing the session")

	err = p.Close()
	assert.Nil(t, err, "Should not return a error when closing the provider")
}

