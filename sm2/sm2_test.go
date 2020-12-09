package sm2

import (
	"crypto"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Set key usage limit for test env
const maxKeyLimit = 10
const testSignAndVerifyKeyId = "acc39758-a2ff-4ff2-900e-8a2cd5d37335"
const testEncryptAndDecryptKeyId = "db20aafe-c953-43b7-914e-565cc5a7381f"

func TestSignAndVerify(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter(testSignAndVerifyKeyId, SignAndVerify)

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
}

func TestEncryptAndDecryptWithPublicKey(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter(testEncryptAndDecryptKeyId, EncryptAndDecrypt)

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
}

func TestEncryptAndDecrypt(t *testing.T) {
	adapter, err := CreateSm2KeyAdapter(testEncryptAndDecryptKeyId, EncryptAndDecrypt)

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
}

func TestIsCryptoSigner(t *testing.T) {
	var duck interface{}
	duck, err := CreateSm2KeyAdapter(testSignAndVerifyKeyId, SignAndVerify)
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
	duck, err := CreateSm2KeyAdapter(testSignAndVerifyKeyId, SignAndVerify)
	if err != nil {
		t.Fatalf("failed to create sm2 key adapter, Got err: %s", err)
	}

	_, ok := duck.(crypto.Decrypter)
	if !ok {
		t.Fatalf("sm2 key adapter is not crypto.Decrypter")
	}
}

func TestListKeys(t *testing.T) {
	allKeys, err := ListKyes()
	if err != nil {
		t.Fatalf("failed to list sm2 keys, Got err: %s", err)
	}
	t.Logf("Used Total: %d keys", len(allKeys))
	for i, k := range allKeys {
		t.Log("Key ", i, ": ", k)
	}

	if len(allKeys) >= maxKeyLimit {
		t.Fatalf("Should not use more then %d keys", maxKeyLimit)
	}
}
