package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/crypto/nacl/box"
)

var channelPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,24}$`)

var (
	signDomain = []byte("c2dip:fragment:v3\x00")
	sealDomain = []byte("c2dip:message:v3\x00")
)

const EncryptionOverhead = box.Overhead + 32 + len("c2dip:message:v3\x00")

type document struct {
	Version              int    `json:"version"`
	Channel              string `json:"channel"`
	Role                 string `json:"role"`
	SigningPrivate       string `json:"signing_private"`
	EncryptionPrivate    string `json:"encryption_private"`
	PeerSigningPublic    string `json:"peer_signing_public"`
	PeerEncryptionPublic string `json:"peer_encryption_public"`
}

type ChannelKeys struct {
	Channel        string
	Role           string
	Signing        ed25519.PrivateKey
	Encryption     *[32]byte
	PeerSigning    ed25519.PublicKey
	PeerEncryption *[32]byte
}

func validateChannel(channel string) error {
	if !channelPattern.MatchString(channel) {
		return errors.New("invalid channel name in key bundle")
	}
	return nil
}

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func decode(value string) ([]byte, error) {
	if len(value) != 43 {
		return nil, errors.New("key fields must encode exactly 32 bytes")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || encode(raw) != value {
		return nil, errors.New("invalid key encoding")
	}
	return raw, nil
}

func array32(raw []byte) *[32]byte {
	result := new([32]byte)
	copy(result[:], raw)
	return result
}

func GeneratePair(channel string) (*ChannelKeys, *ChannelKeys, error) {
	if err := validateChannel(channel); err != nil {
		return nil, nil, err
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	receiverPublic, receiverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	clientBoxPublic, clientBoxPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	receiverBoxPublic, receiverBoxPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	client := &ChannelKeys{channel, "client", clientPrivate, clientBoxPrivate, receiverPublic, receiverBoxPublic}
	receiver := &ChannelKeys{channel, "receiver", receiverPrivate, receiverBoxPrivate, clientPublic, clientBoxPublic}
	return client, receiver, nil
}

func (k *ChannelKeys) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(k.Channel))
	h.Write([]byte{0})
	h.Write([]byte(k.Role))
	h.Write([]byte{0})
	h.Write(k.Signing.Public().(ed25519.PublicKey))
	h.Write(k.EncryptionPublic()[:])
	h.Write(k.PeerSigning)
	h.Write(k.PeerEncryption[:])
	return hex.EncodeToString(h.Sum(nil))
}

func (k *ChannelKeys) EncryptionPublic() *[32]byte {
	var public [32]byte
	// box.GenerateKey uses Curve25519; X25519 reconstructs its public key.
	curve25519ScalarBaseMult(&public, k.Encryption)
	return &public
}

func curve25519ScalarBaseMult(public, private *[32]byte) {
	// GenerateKey's public derivation is exposed by box through SealAnonymous only indirectly.
	// x/crypto/curve25519 keeps this operation pure Go and compatible with libsodium.
	derived, err := curve25519X25519(private[:])
	if err != nil {
		panic(err)
	}
	copy(public[:], derived)
}

var curve25519X25519 = func(private []byte) ([]byte, error) {
	return x25519(private)
}

func (k *ChannelKeys) Sign(data []byte) []byte {
	return ed25519.Sign(k.Signing, append(append([]byte{}, signDomain...), data...))
}

func (k *ChannelKeys) Verify(data, signature []byte, includeOutgoing bool) error {
	message := append(append([]byte{}, signDomain...), data...)
	if ed25519.Verify(k.PeerSigning, message, signature) {
		return nil
	}
	if includeOutgoing && ed25519.Verify(k.Signing.Public().(ed25519.PublicKey), message, signature) {
		return nil
	}
	return errors.New("fragment signature verification failed")
}

func (k *ChannelKeys) Encrypt(plaintext []byte) ([]byte, error) {
	return box.SealAnonymous(nil, append(append([]byte{}, sealDomain...), plaintext...), k.PeerEncryption, rand.Reader)
}

func (k *ChannelKeys) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, k.EncryptionPublic(), k.Encryption)
	if !ok {
		return nil, errors.New("message decryption failed")
	}
	if len(plaintext) < len(sealDomain) || string(plaintext[:len(sealDomain)]) != string(sealDomain) {
		return nil, errors.New("invalid encrypted message domain")
	}
	return plaintext[len(sealDomain):], nil
}

func (k *ChannelKeys) document() document {
	return document{1, k.Channel, k.Role, encode(k.Signing.Seed()), encode(k.Encryption[:]),
		encode(k.PeerSigning), encode(k.PeerEncryption[:])}
}

func Load(path, channel, role string) (*ChannelKeys, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw, channel, role)
}

func Parse(raw []byte, channel, role string) (*ChannelKeys, error) {
	if len(raw) > 8192 {
		return nil, errors.New("key bundle is too large")
	}
	expected := map[string]bool{"version": true, "channel": true, "role": true, "signing_private": true,
		"encryption_private": true, "peer_signing_public": true, "peer_encryption_public": true}
	fieldDecoder := json.NewDecoder(bytesReader(raw))
	token, fieldErr := fieldDecoder.Token()
	if fieldErr != nil || token != json.Delim('{') {
		return nil, errors.New("invalid key bundle")
	}
	seen := map[string]bool{}
	for fieldDecoder.More() {
		keyToken, err := fieldDecoder.Token()
		if err != nil {
			return nil, errors.New("invalid key bundle")
		}
		name, ok := keyToken.(string)
		if !ok || !expected[name] || seen[name] {
			return nil, errors.New("unexpected, missing, or duplicate key-bundle field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := fieldDecoder.Decode(&value); err != nil {
			return nil, errors.New("invalid key bundle")
		}
	}
	if _, err := fieldDecoder.Token(); err != nil || len(seen) != len(expected) {
		return nil, errors.New("unexpected or missing key-bundle fields")
	}
	var trailing any
	if err := fieldDecoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid key bundle")
	}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid key bundle: %w", err)
	}
	if doc.Version != 1 {
		return nil, errors.New("unsupported key-bundle version")
	}
	if err := validateChannel(doc.Channel); err != nil {
		return nil, err
	}
	if channel != "" && doc.Channel != channel {
		return nil, errors.New("key bundle belongs to a different channel")
	}
	if doc.Role != "client" && doc.Role != "receiver" || role != "" && doc.Role != role {
		return nil, errors.New("key bundle belongs to a different endpoint role")
	}
	signing, err := decode(doc.SigningPrivate)
	if err != nil {
		return nil, err
	}
	encryption, err := decode(doc.EncryptionPrivate)
	if err != nil {
		return nil, err
	}
	peerSigning, err := decode(doc.PeerSigningPublic)
	if err != nil {
		return nil, err
	}
	peerEncryption, err := decode(doc.PeerEncryptionPublic)
	if err != nil {
		return nil, err
	}
	return &ChannelKeys{doc.Channel, doc.Role, ed25519.NewKeyFromSeed(signing), array32(encryption),
		ed25519.PublicKey(peerSigning), array32(peerEncryption)}, nil
}

func writeBundle(path string, k *ChannelKeys) error {
	raw, err := json.MarshalIndent(k.document(), "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func CreateChannel(parent, channel string) ([]string, error) {
	if err := validateChannel(channel); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	target := filepath.Join(parent, channel)
	if err := os.Mkdir(target, 0o700); err != nil {
		return nil, err
	}
	client, receiver, err := GeneratePair(channel)
	if err != nil {
		os.Remove(target)
		return nil, err
	}
	paths := []string{filepath.Join(target, "client.json"), filepath.Join(target, "receiver.json")}
	for index, key := range []*ChannelKeys{client, receiver} {
		if err := writeBundle(paths[index], key); err != nil {
			for _, path := range paths {
				os.Remove(path)
			}
			os.Remove(target)
			return nil, err
		}
	}
	return paths, nil
}
