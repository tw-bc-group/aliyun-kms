package sm4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testSm4KeyId = "xxxxxx"

func TestEncryptAndDecrypt(t *testing.T) {
	adapter, err := CreateSm4KeyAdapter(testSm4KeyId)
	if err != nil {
		t.Fatalf("failed to create adapter key, Got err: %s", err)
	}

	plainText := []byte("test adapter")

	cipherText, err := adapter.Encrypt(plainText)
	if err != nil {
		t.Fatalf("failed to adapter encrypt, Got err: %s", err)
	}

	decryptText, err := adapter.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("failed to adapter decrypt, Got err: %s", err)
	}

	assert.Equal(t, plainText, decryptText, "decrypted should same as plain text")
}
