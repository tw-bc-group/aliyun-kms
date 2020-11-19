package sm2

import (
	"encoding/base64"
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm3"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const requestScheme = "https"
const sm2SignAlgorithm = "SM2DSA"
const sm2EncryptAlgorithm = "SM2PKE"

const (
	EncryptAndDecrypt = 1 + iota
	SignAndVerify
)

type KeyAdapter struct {
	client     *kms.Client
	usage      int
	keyID      string
	keyVersion string
}

func keyUsageString(keyUsage int) string {
	switch keyUsage {
	case EncryptAndDecrypt:
		return "ENCRYPT/DECRYPT"
	default:
		return "SIGN/VERIFY"
	}
}

func sm3Digest(message []byte) string {
	return base64.StdEncoding.EncodeToString(sm3.Sm3Sum(message))
}

func CreateSm2KeyAdapter(client *kms.Client, usage int, keyID string) (*KeyAdapter, error) {
	if usage != EncryptAndDecrypt && usage != SignAndVerify {
		usage = SignAndVerify
	}

	sm2 := &KeyAdapter{
		client: client,
		usage:  usage,
	}

	if keyID == "" {
		err := sm2.CreateKey()
		if err != nil {
			return nil, err
		}
	}

	return sm2, nil
}

func (sm2 *KeyAdapter) KeyID() string {
	return sm2.keyID
}

func (sm2 *KeyAdapter) CreateKey() error {
	createKeyReq := kms.CreateCreateKeyRequest()
	createKeyReq.Scheme = requestScheme
	createKeyReq.KeySpec = "EC_SM2"
	createKeyReq.KeyUsage = keyUsageString(sm2.usage)

	createKeyResp, err := sm2.client.CreateKey(createKeyReq)
	if err != nil {
		return err
	}

	sm2.keyID = createKeyResp.KeyMetadata.KeyId

	listKeyVersionsReq := kms.CreateListKeyVersionsRequest()
	listKeyVersionsReq.Scheme = requestScheme
	listKeyVersionsReq.KeyId = sm2.keyID

	listKeyVersionsResp, err := sm2.client.ListKeyVersions(listKeyVersionsReq)
	if err != nil {
		return err
	}

	sm2.keyVersion = listKeyVersionsResp.KeyVersions.KeyVersion[0].KeyVersionId

	return nil
}

func (sm2 *KeyAdapter) GetPublicKey() (string, error) {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.KeyVersionId = sm2.keyVersion

	response, err := sm2.client.GetPublicKey(request)
	if err != nil {
		return "", err
	}

	return response.PublicKey, nil
}

func (sm2 *KeyAdapter) AsymmetricSign(message []byte) (string, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return "", errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return "", errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricSignRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = sm2.keyVersion
	request.Digest = sm3Digest(message)

	response, err := sm2.client.AsymmetricSign(request)
	if err != nil {
		return "", err
	}

	return response.Value, nil
}

func (sm2 *KeyAdapter) AsymmetricVerify(message []byte, signature string) (bool, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return false, errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return false, errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricVerifyRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = sm2.keyVersion
	request.Digest = sm3Digest(message)
	request.Value = signature

	response, err := sm2.client.AsymmetricVerify(request)

	if err != nil {
		return false, err
	}

	return response.Value, nil
}

func (sm2 *KeyAdapter) AsymmetricEncrypt(plainText []byte) (string, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return "", errors.New("need create sm2 key first")
	}

	if sm2.usage != EncryptAndDecrypt {
		return "", errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricEncryptRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.KeyVersionId = sm2.keyVersion
	request.Algorithm = sm2EncryptAlgorithm
	request.Plaintext = base64.StdEncoding.EncodeToString(plainText)

	response, err := sm2.client.AsymmetricEncrypt(request)
	if err != nil {
		return "", err
	}
	return response.CiphertextBlob, nil
}

func (sm2 *KeyAdapter) AsymmetricDecrypt(cipherText string) ([]byte, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return nil, errors.New("need create sm2 key first")
	}

	if sm2.usage != EncryptAndDecrypt {
		return nil, errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricDecryptRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.KeyVersionId = sm2.keyVersion
	request.Algorithm = sm2EncryptAlgorithm
	request.CiphertextBlob = cipherText

	response, err := sm2.client.AsymmetricDecrypt(request)
	if err != nil {
		return nil, err
	}

	plainText, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func (sm2 *KeyAdapter) ScheduleKeyDeletion() error {
	request := kms.CreateScheduleKeyDeletionRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.PendingWindowInDays = requests.NewInteger(7)

	_, err := sm2.client.ScheduleKeyDeletion(request)
	return err
}
