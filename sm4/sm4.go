package sm4

import (
	"encoding/base64"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const requestScheme = "https"

type KeyAdapter struct {
	client *kms.Client
	keyID  string
}

func CreateSm4KeyAdapter(client *kms.Client, keyID string) (*KeyAdapter, error) {
	sm4 := &KeyAdapter{
		client: client,
	}

	if keyID == "" {
		err := sm4.CreateKey()
		if err != nil {
			return nil, err
		}
	}

	return sm4, nil
}

func (sm4 *KeyAdapter) CreateKey() error {
	request := kms.CreateCreateKeyRequest()
	request.Scheme = requestScheme
	request.KeySpec = "Aliyun_SM4"

	response, err := sm4.client.CreateKey(request)
	if err != nil {
		return err
	}

	sm4.keyID = response.KeyMetadata.KeyId
	return nil
}

func (sm4 *KeyAdapter) Encrypt(plainText []byte) ([]byte, error) {
	request := kms.CreateEncryptRequest()
	request.Scheme = requestScheme
	request.KeyId = sm4.keyID
	request.Plaintext = base64.StdEncoding.EncodeToString(plainText)

	response, err := sm4.client.Encrypt(request)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.CiphertextBlob)
}

func (sm4 *KeyAdapter) Decrypt(cipherText []byte) ([]byte, error) {
	request := kms.CreateDecryptRequest()
	request.Scheme = requestScheme
	request.CiphertextBlob = base64.StdEncoding.EncodeToString(cipherText)

	response, err := sm4.client.Decrypt(request)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.Plaintext)
}

func (sm4 *KeyAdapter) ScheduleKeyDeletion() error {
	request := kms.CreateScheduleKeyDeletionRequest()
	request.Scheme = requestScheme
	request.KeyId = sm4.keyID
	request.PendingWindowInDays = requests.NewInteger(7)

	_, err := sm4.client.ScheduleKeyDeletion(request)
	return err
}
