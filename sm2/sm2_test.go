package sm2

import (
	"crypto"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignAndVerify(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("", SignAndVerify)

	if err != nil {
		t.Fatalf("failed to create adapter sign key, Got err: %s", err)
	}

	message := []byte("test sign verify")

	signature, err := adapter.AsymmetricSign(message)
	if err != nil {
		t.Fatalf("failed to adapter asymmetric sign, Got err: %s", err)
	}

	verify, err := adapter.AsymmetricVerify(message, signature)
	if err != nil {
		t.Fatalf("failed to adapter asymmetric verify, Got err: %s", err)
	}

	assert.Equal(t, verify, true, "verify should be success")

	if err = adapter.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule adapter key deletion, Got err: %s", err)
	}
}


func TestEncryptAndDecryptWithPublicKey(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("", EncryptAndDecrypt)

	if err != nil {
		t.Fatalf("failed to create sm2 encrypt key, Got err: %s", err)
	}

	message := []byte("test crypto")

	publicKey := adapter.PublicKey()

	cipher, err := sm2.Encrypt(publicKey, message, nil)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := adapter.AsymmetricDecrypt(cipher)
	if err != nil {
		t.Fatalf("failed to sm2 asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = adapter.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule sm2 key deletion, Got err: %s", err)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter("", EncryptAndDecrypt)

	if err != nil {
		t.Fatalf("failed to create adapter encrypt key, Got err: %s", err)
	}

	message := []byte("test crypto")

	cipherText, err := adapter.AsymmetricEncrypt(message)
	if err != nil {
		t.Fatalf("failed to adapter asymmetric encrypt, Got err: %s", err)
	}

	decryptText, err := adapter.AsymmetricDecrypt(cipherText)
	if err != nil {
		t.Fatalf("failed to adapter asymmetric decrypt, Got err: %s", err)
	}

	assert.Equal(t, message, decryptText, "decrypted should same as plain text")

	if err = adapter.ScheduleKeyDeletion(); err != nil {
		t.Fatalf("failed to schedule adapter key deletion, Got err: %s", err)
	}
}

func TestIsCryptoSigner(t *testing.T) {
	var duck interface{}
	duck, err := CreateSm2KeyAdapter("", SignAndVerify)
	if err != nil {
		t.Fatalf("failed to create sm2 key adapter, Got err: %s", err)
	}

	_, ok := duck.(crypto.Signer)
	if !ok {
		t.Fatalf("sm2 key adapter is not crypto.Signer")
	}
}


func TestIsCryptoDecrypter(t *testing.T) {
	var duck interface{}
	duck, err := CreateSm2KeyAdapter("", SignAndVerify)
	if err != nil {
		t.Fatalf("failed to create sm2 key adapter, Got err: %s", err)
	}

	_, ok := duck.(crypto.Decrypter)
	if !ok {
		t.Fatalf("sm2 key adapter is not crypto.Decrypter")
	}
}
