package sm4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecrypt(t *testing.T) {
	adapter, err := CreateSm4KeyAdapter("")
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

	if err = adapter.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule adapter key deletion, Got err: %s", err)
	}
}
