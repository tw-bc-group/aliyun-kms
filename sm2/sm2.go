package sm2

import (
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/tw-bc-group/aliyun-kms/comm"
	"io"
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

func (sm2 *KeyAdapter) sm3Digest(message []byte) (string, error) {
	pubKey, err := sm2.GetPublicKey()

	if err != nil {
		return "", err
	}

	digest, err := pubKey.Sm3Digest(message, []byte{})
	if err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(digest), nil
}

func keyUsageString(keyUsage int) string {
	switch keyUsage {
	case EncryptAndDecrypt:
		return "ENCRYPT/DECRYPT"
	default:
		return "SIGN/VERIFY"
	}
}

func CreateSm2KeyAdapter(keyID string, usage int) (*KeyAdapter, error) {
	if usage != EncryptAndDecrypt && usage != SignAndVerify {
		usage = SignAndVerify
	}

	client, err := comm.CreateKmsClient()
	if err != nil {
		return nil, err
	}

	adapter := &KeyAdapter{
		client: client,
		usage:  usage,
		keyID:  keyID,
	}

	err = adapter.CreateKey()
	if err != nil {
		return nil, err
	}

	return adapter, nil
}

func (sm2 *KeyAdapter) KeyID() string {
	return sm2.keyID
}

func (sm2 *KeyAdapter) CreateKey() error {
	// set keyID already
	if sm2.keyID == "" {
		request := kms.CreateCreateKeyRequest()
		request.Scheme = requestScheme
		request.KeySpec = "EC_SM2"
		request.KeyUsage = keyUsageString(sm2.usage)

		response, err := sm2.client.CreateKey(request)
		if err != nil {
			return err
		}
		sm2.keyID = response.KeyMetadata.KeyId
	}

	request := kms.CreateListKeyVersionsRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID

	response, err := sm2.client.ListKeyVersions(request)
	if err != nil {
		return err
	}

	sm2.keyVersion = response.KeyVersions.KeyVersion[0].KeyVersionId

	return nil
}

func (sm2 *KeyAdapter) GetPublicKey() (*sm2.PublicKey, error) {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.KeyVersionId = sm2.keyVersion

	response, err := sm2.client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(response.PublicKey))
	pubKey, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func (sm2 *KeyAdapter) AsymmetricSign(message []byte) ([]byte, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return nil, errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return nil, errors.New("unexpected key usage")
	}

	digest, err := sm2.sm3Digest(message)
	if err != nil {
		return nil, err
	}

	request := kms.CreateAsymmetricSignRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = sm2.keyVersion
	request.Digest = digest

	response, err := sm2.client.AsymmetricSign(request)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(response.Value)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (sm2 *KeyAdapter) AsymmetricVerify(message, signature []byte, ) (bool, error) {
	if sm2.keyID == "" || sm2.keyVersion == "" {
		return false, errors.New("need create sm2 key first")
	}

	if sm2.usage != SignAndVerify {
		return false, errors.New("unexpected key usage")
	}

	digest, err := sm2.sm3Digest(message)
	if err != nil {
		return false, err
	}

	request := kms.CreateAsymmetricVerifyRequest()
	request.Scheme = requestScheme
	request.KeyId = sm2.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = sm2.keyVersion
	request.Digest = digest
	request.Value = base64.StdEncoding.EncodeToString(signature)

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

// implements crypto.Signer
func (sm2 *KeyAdapter) TryIntoCryptoSigner() (crypto.Signer, error) {
	pubKey, err := sm2.GetPublicKey()
	if err != nil {
		return nil, err
	}

	return &cryptoSigner{adapter: sm2, pubKey: pubKey}, nil
}

type cryptoSigner struct {
	adapter *KeyAdapter
	pubKey  crypto.PublicKey
}

func (c *cryptoSigner) Public() crypto.PublicKey {
	return c.pubKey
}

func (c *cryptoSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := c.adapter.AsymmetricSign(message)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
