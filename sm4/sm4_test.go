package sm4

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)


func setupFixture() *kms.Client {
	client, err := kms.NewClientWithAccessKey(os.Getenv("ALIBABA_CLOUD_REGION"),
		os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"), os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))
	if err != nil {
		panic(err)
	}
	return client
}

func TestEncryptAndDecrypt(t *testing.T) {
	client := setupFixture()

	sm4, err := CreateSm4KeyAdapter(client, "")
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
