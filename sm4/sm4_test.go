package sm4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecrypt(t *testing.T) {
	sm4, err := CreateSm4KeyAdapter("")
	if err != nil {
		t.Fatalf("failed to create sm4 key, Got err: %s", err)
	}

	plainText := []byte("test sm4")

	cipherText, err := sm4.Encrypt(plainText)
	if err != nil {
		t.Fatalf("failed to sm4 encrypt, Got err: %s", err)
	}

	decryptText, err := sm4.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("failed to sm4 decrypt, Got err: %s", err)
	}

	assert.Equal(t, plainText, decryptText, "decrypted should same as plain text")

	if err = sm4.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm4 key deletion, Got err: %s", err)
	}
}
