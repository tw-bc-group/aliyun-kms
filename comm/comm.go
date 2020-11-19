package comm

import (
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CreateKmsClient() (*kms.Client, error) {
	client, err := kms.NewClientWithAccessKey(os.Getenv("ALIBABA_CLOUD_REGION"),
		os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"), os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))
	if err != nil {
		return nil, err
	}
	return client, nil
}