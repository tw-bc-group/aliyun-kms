package sm2

import (
	"os"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/stretchr/testify/assert"
)

func setupFixture() *kms.Client {
	client, err := kms.NewClientWithAccessKey(os.Getenv("ALIBABA_CLOUD_REGION"),
		os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"), os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))
	if err != nil {
		panic(err)
	}
	return client
}

func TestSignAndVerify(t *testing.T) {
	client := setupFixture()

	sm2, err := CreateSm2KeyAdapter(client, SignAndVerify, "")

	if err != nil {
		t.Fatalf("failed to create sm2 sign key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	signature, err := sm2.AsymmetricSign(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric sign, Got err: %s", err)
	}

	verify, err := sm2.AsymmetricVerify(message, signature)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric verify, Got err: %s", err)
	}

	assert.Equal(t, verify, true, "verify should be success")

	if err = sm2.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	client := setupFixture()

	sm2, err := CreateSm2KeyAdapter(client, EncryptAndDecrypt, "")

	if err != nil {
		t.Fatalf("failed to create sm2 encrypt key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	plainText, err := sm2.AsymmetricEncrypt(message)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := sm2.AsymmetricDecrypt(plainText)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = sm2.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}
