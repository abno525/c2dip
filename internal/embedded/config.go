package embedded

import "encoding/base64"

var apiKeyEncoded string
var receiverBundleEncoded string

func decode(value string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	return decoded
}

func APIKey() string         { return string(decode(apiKeyEncoded)) }
func ReceiverBundle() []byte { return decode(receiverBundleEncoded) }
