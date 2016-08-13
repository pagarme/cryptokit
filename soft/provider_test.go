package soft

import (
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestProviderLifecycle(t *testing.T) {
	defer os.Remove("testdb.db")

	p, err := New("testdb.db")
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

