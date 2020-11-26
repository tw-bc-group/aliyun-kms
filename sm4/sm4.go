package sm4

import (
	"encoding/base64"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/tw-bc-group/aliyun-kms/comm"
)

const requestScheme = "https"

type KeyAdapter struct {
	client *kms.Client
	keyID  string
}

func CreateSm4KeyAdapter(keyID string) (*KeyAdapter, error) {
	client, err := comm.CreateKmsClient()
	if err != nil {
		return nil, err
	}

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

func (adapter *KeyAdapter) CreateKey() error {
	request := kms.CreateCreateKeyRequest()
	request.Scheme = requestScheme
	request.KeySpec = "Aliyun_SM4"

	response, err := adapter.client.CreateKey(request)
	if err != nil {
		return err
	}

	adapter.keyID = response.KeyMetadata.KeyId
	return nil
}

func (adapter *KeyAdapter) Encrypt(plainText []byte) ([]byte, error) {
	request := kms.CreateEncryptRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.Plaintext = base64.StdEncoding.EncodeToString(plainText)

	response, err := adapter.client.Encrypt(request)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.CiphertextBlob)
}

func (adapter *KeyAdapter) Decrypt(cipherText []byte) ([]byte, error) {
	request := kms.CreateDecryptRequest()
	request.Scheme = requestScheme
	request.CiphertextBlob = base64.StdEncoding.EncodeToString(cipherText)

	response, err := adapter.client.Decrypt(request)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.Plaintext)
}

func (adapter *KeyAdapter) ScheduleKeyDeletion() error {
	request := kms.CreateScheduleKeyDeletionRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.PendingWindowInDays = requests.NewInteger(7)

	_, err := adapter.client.ScheduleKeyDeletion(request)
	return err
}
