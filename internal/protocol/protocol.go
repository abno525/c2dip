package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"c2dip/internal/keys"
)

const (
	MaxName     = 500
	MaxParts    = 4096
	MaxData     = 1024 * 1024
	MaxMeta     = 4096
	MaxBody     = 4 + MaxMeta + MaxData
	MaxWireBody = MaxBody + keys.EncryptionOverhead
	MinTTL      = 3600
	MaxTTL      = 30 * 86400
	Prefix      = "c2d3"
)

var terminal = map[string]bool{"succeeded": true, "failed": true, "timed_out": true,
	"cancelled": true, "output_limit": true, "uncertain": true, "expired": true}

func IsTerminal(state string) bool { return terminal[state] }

type Message struct {
	ID, Channel, Sender, Recipient, Kind string
	Created, Expires                     int64
	Metadata                             map[string]any
	Payload                              []byte
}

type Header struct {
	ID        string `json:"id"`
	Channel   string `json:"channel"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Kind      string `json:"kind"`
	Digest    string `json:"digest"`
	Created   int64  `json:"created"`
	Expires   int64  `json:"expires"`
	Total     int    `json:"total"`
}

type Frame struct {
	Header Header
	Index  int
	Data   []byte
}

func NodeName(value string) (string, error) {
	if len(value) < 1 || len(value) > 24 {
		return "", errors.New("channel and node IDs must be 1–24 ASCII letters, digits, '_' or '-'")
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return "", errors.New("channel and node IDs must be 1–24 ASCII letters, digits, '_' or '-'")
		}
	}
	return value, nil
}

func Identifier(value string) (string, error) {
	if len(value) != 32 {
		return "", errors.New("invalid message ID")
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return "", errors.New("invalid message ID")
		}
	}
	return value, nil
}

func integer(value any, low, high int64) (int64, error) {
	var number int64
	switch typed := value.(type) {
	case int:
		number = int64(typed)
	case int64:
		number = typed
	case int32:
		number = int64(typed)
	case json.Number:
		var err error
		number, err = typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("expected an integer between %d and %d", low, high)
		}
	default:
		return 0, fmt.Errorf("expected an integer between %d and %d", low, high)
	}
	if number < low || number > high {
		return 0, fmt.Errorf("expected an integer between %d and %d", low, high)
	}
	return number, nil
}

func text(value any, limit int) (string, error) {
	stringValue, ok := value.(string)
	if !ok || !utf8.ValidString(stringValue) || strings.ContainsRune(stringValue, 0) || len([]byte(stringValue)) > limit {
		return "", errors.New("invalid or oversized text field")
	}
	return stringValue, nil
}

func exactFields(metadata map[string]any, required, optional []string) bool {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, field := range required {
		allowed[field] = true
		if _, ok := metadata[field]; !ok {
			return false
		}
	}
	for _, field := range optional {
		allowed[field] = true
	}
	for field := range metadata {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func ValidateBody(kind string, metadata map[string]any, payload []byte) error {
	if metadata == nil || len(payload) > MaxData {
		return errors.New("invalid or oversized message body")
	}
	switch kind {
	case "c":
		if !exactFields(metadata, []string{"timeout"}, nil) {
			return errors.New("unexpected or missing metadata fields")
		}
		if _, err := integer(metadata["timeout"], 1, 86400); err != nil {
			return err
		}
		command, err := text(string(payload), 16384)
		if err != nil || strings.TrimSpace(command) == "" {
			return errors.New("empty or invalid command")
		}
	case "g":
		if !exactFields(metadata, nil, nil) {
			return errors.New("unexpected metadata fields")
		}
		path, err := text(string(payload), 4096)
		if err != nil || path == "" {
			return errors.New("empty or invalid download path")
		}
	case "f":
		if !exactFields(metadata, []string{"name"}, []string{"reply_to"}) {
			return errors.New("unexpected or missing metadata fields")
		}
		name, err := text(metadata["name"], 200)
		if err != nil || name == "" {
			return errors.New("empty or invalid file name")
		}
		if value, ok := metadata["reply_to"]; ok {
			if _, err := Identifier(anyString(value)); err != nil {
				return err
			}
		}
	case "a":
		if !exactFields(metadata, []string{"ref"}, nil) || len(payload) != 0 {
			return errors.New("invalid acknowledgement")
		}
		if _, err := Identifier(anyString(metadata["ref"])); err != nil {
			return err
		}
	case "s", "k":
		optional := []string(nil)
		if kind == "s" {
			optional = []string{"output"}
		}
		if !exactFields(metadata, []string{"job"}, optional) || len(payload) != 0 {
			return errors.New("invalid control message")
		}
		if _, err := Identifier(anyString(metadata["job"])); err != nil {
			return err
		}
		if output, ok := metadata["output"]; ok {
			if _, ok := output.(bool); !ok {
				return errors.New("output must be a boolean")
			}
		}
	case "r":
		if !exactFields(metadata, []string{"reply_to", "state", "code", "detail"}, []string{"job", "path"}) {
			return errors.New("unexpected or missing metadata fields")
		}
		if _, err := Identifier(anyString(metadata["reply_to"])); err != nil {
			return err
		}
		state, ok := metadata["state"].(string)
		if !ok || (!IsTerminal(state) && state != "queued" && state != "running" && state != "not_found" && state != "cancel_requested") {
			return errors.New("invalid job state")
		}
		if metadata["code"] != nil {
			if _, err := integer(metadata["code"], -255, 255); err != nil {
				return err
			}
		}
		if _, err := text(metadata["detail"], 1024); err != nil {
			return err
		}
		if job, ok := metadata["job"]; ok {
			if _, err := Identifier(anyString(job)); err != nil {
				return err
			}
		}
		if path, ok := metadata["path"]; ok {
			if _, err := text(path, 2048); err != nil {
				return err
			}
		}
	default:
		return errors.New("unknown message kind")
	}
	return nil
}

func anyString(value any) string { result, _ := value.(string); return result }

func PackBody(kind string, metadata map[string]any, payload []byte) ([]byte, error) {
	if err := ValidateBody(kind, metadata, payload); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(metadata); err != nil {
		return nil, err
	}
	header := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	if len(header) > MaxMeta {
		return nil, errors.New("message metadata is too large")
	}
	body := make([]byte, 4+len(header)+len(payload))
	binary.BigEndian.PutUint32(body, uint32(len(header)))
	copy(body[4:], header)
	copy(body[4+len(header):], payload)
	return body, nil
}

func decodeMetadata(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("metadata must be an object")
	}
	result := map[string]any{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("invalid metadata key")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("duplicate metadata field")
		}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) == nil {
		return nil, errors.New("trailing metadata")
	}
	return result, nil
}

func UnpackBody(kind string, body []byte) (map[string]any, []byte, error) {
	if len(body) < 4 || len(body) > MaxBody {
		return nil, nil, errors.New("invalid message size")
	}
	size := int(binary.BigEndian.Uint32(body[:4]))
	if size < 2 || size > MaxMeta || 4+size > len(body) {
		return nil, nil, errors.New("invalid metadata length")
	}
	metadata, err := decodeMetadata(body[4 : 4+size])
	if err != nil {
		return nil, nil, err
	}
	payload := append([]byte(nil), body[4+size:]...)
	if err := ValidateBody(kind, metadata, payload); err != nil {
		return nil, nil, err
	}
	return metadata, payload, nil
}

func (m Message) Body() ([]byte, error) { return PackBody(m.Kind, m.Metadata, m.Payload) }

func NewMessage(channel, sender, recipient, kind string, metadata map[string]any, payload []byte,
	ttl int64, now time.Time, messageID string) (Message, error) {
	var err error
	if channel, err = NodeName(channel); err != nil {
		return Message{}, err
	}
	if sender, err = NodeName(sender); err != nil {
		return Message{}, err
	}
	if recipient, err = NodeName(recipient); err != nil {
		return Message{}, err
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return Message{}, errors.New("invalid message lifetime")
	}
	if messageID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return Message{}, err
		}
		messageID = hex.EncodeToString(raw)
	}
	if _, err := Identifier(messageID); err != nil {
		return Message{}, err
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	created := now.Unix()
	message := Message{messageID, channel, sender, recipient, kind, created, created + ttl, metadata, append([]byte(nil), payload...)}
	_, err = message.Body()
	return message, err
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
func unb64(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || b64(raw) != value {
		return nil, errors.New("invalid or non-canonical base64")
	}
	return raw, nil
}

func filename(message Message, digest string, index, total int, data []byte, channelKeys *keys.ChannelKeys) string {
	fields := []string{Prefix, message.Channel, message.Sender, message.Recipient, message.ID, message.Kind,
		strconv.FormatInt(message.Created, 10), strconv.FormatInt(message.Expires, 10), strconv.Itoa(index),
		strconv.Itoa(total), digest, b64(data)}
	signed := strings.Join(fields, ".")
	return signed + "." + b64(channelKeys.Sign([]byte(signed))) + ".png"
}

func Encode(message Message, channelKeys *keys.ChannelKeys) ([]string, error) {
	if channelKeys == nil || channelKeys.Channel != message.Channel {
		return nil, errors.New("a matching channel key bundle is required")
	}
	plaintext, err := message.Body()
	if err != nil {
		return nil, err
	}
	body, err := channelKeys.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	digestRaw := sha256.Sum256(body)
	digest := b64(digestRaw[:])
	low, high := 0, MaxName
	for low < high {
		middle := (low + high + 1) / 2
		if len(filename(message, digest, MaxParts-1, MaxParts, make([]byte, middle), channelKeys)) <= MaxName {
			low = middle
		} else {
			high = middle - 1
		}
	}
	if low == 0 {
		return nil, errors.New("envelope leaves no space for data")
	}
	total := int(math.Ceil(float64(len(body)) / float64(low)))
	if total > MaxParts {
		return nil, fmt.Errorf("message needs %d files; maximum is %d", total, MaxParts)
	}
	result := make([]string, 0, total)
	for offset, index := 0, 0; offset < len(body); offset, index = offset+low, index+1 {
		end := min(offset+low, len(body))
		result = append(result, filename(message, digest, index, total, body[offset:end], channelKeys))
	}
	return result, nil
}

func DecodeFrame(name string, channelKeys *keys.ChannelKeys, channel, recipient string, now time.Time,
	allowExpired, includeOutgoing bool) (*Frame, error) {
	if !strings.HasPrefix(name, Prefix+".") {
		return nil, nil
	}
	if len(name) > MaxName || !isASCII(name) {
		return nil, errors.New("oversized or non-ASCII filename")
	}
	fields := strings.Split(name, ".")
	if len(fields) != 14 || fields[13] != "png" {
		return nil, errors.New("invalid envelope")
	}
	ch, source, destination, id, kind := fields[1], fields[2], fields[3], fields[4], fields[5]
	if channelKeys == nil || ch != channelKeys.Channel || channel != "" && ch != channel || recipient != "" && destination != recipient {
		return nil, nil
	}
	signature, err := unb64(fields[12])
	if err != nil {
		return nil, err
	}
	if err := channelKeys.Verify([]byte(strings.Join(fields[:12], ".")), signature, includeOutgoing); err != nil {
		return nil, err
	}
	if _, err := NodeName(ch); err != nil {
		return nil, err
	}
	if _, err := NodeName(source); err != nil {
		return nil, err
	}
	if _, err := NodeName(destination); err != nil {
		return nil, err
	}
	if _, err := Identifier(id); err != nil {
		return nil, err
	}
	if !strings.Contains("cfrgask", kind) || len(kind) != 1 {
		return nil, errors.New("unknown message kind")
	}
	created, err := canonicalInt(fields[6])
	if err != nil {
		return nil, err
	}
	expires, err := canonicalInt(fields[7])
	if err != nil {
		return nil, err
	}
	index64, err := canonicalInt(fields[8])
	if err != nil {
		return nil, err
	}
	total64, err := canonicalInt(fields[9])
	if err != nil {
		return nil, err
	}
	if total64 < 1 || total64 > MaxParts || index64 < 0 || index64 >= total64 {
		return nil, errors.New("invalid sequence header")
	}
	if expires-created < MinTTL || expires-created > MaxTTL {
		return nil, errors.New("invalid message lifetime")
	}
	if created > now.Unix()+300 || !allowExpired && expires <= now.Unix() {
		return nil, errors.New("message is expired or from the future")
	}
	digest, err := unb64(fields[10])
	if err != nil || len(digest) != 32 {
		return nil, errors.New("invalid message digest")
	}
	data, err := unb64(fields[11])
	if err != nil || len(data) == 0 {
		return nil, errors.New("empty or invalid chunk")
	}
	return &Frame{Header{ID: id, Channel: ch, Sender: source, Recipient: destination, Kind: kind,
		Digest: fields[10], Created: created, Expires: expires, Total: int(total64)}, int(index64), data}, nil
}

func canonicalInt(value string) (int64, error) {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return 0, errors.New("invalid numeric header")
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return 0, errors.New("invalid numeric header")
		}
	}
	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid numeric header")
	}
	return result, nil
}

func isASCII(value string) bool {
	for _, character := range []byte(value) {
		if character >= 128 {
			return false
		}
	}
	return true
}

func Assemble(frames []Frame, channelKeys *keys.ChannelKeys) (Message, error) {
	if len(frames) == 0 {
		return Message{}, errors.New("missing message chunks")
	}
	header := frames[0].Header
	chunks := make(map[int][]byte)
	size := 0
	for _, frame := range frames {
		if frame.Header != header || frame.Index < 0 || frame.Index >= header.Total {
			return Message{}, errors.New("inconsistent message headers")
		}
		if previous, ok := chunks[frame.Index]; ok && !bytes.Equal(previous, frame.Data) {
			return Message{}, errors.New("conflicting duplicate chunk")
		}
		if _, ok := chunks[frame.Index]; !ok {
			chunks[frame.Index] = frame.Data
			size += len(frame.Data)
		}
	}
	if len(chunks) != header.Total {
		return Message{}, errors.New("missing message chunks")
	}
	if size > MaxWireBody {
		return Message{}, errors.New("assembled message is too large")
	}
	body := make([]byte, 0, size)
	for index := range header.Total {
		body = append(body, chunks[index]...)
	}
	digest := sha256.Sum256(body)
	expected, _ := unb64(header.Digest)
	if len(expected) != 32 || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return Message{}, errors.New("message checksum mismatch")
	}
	if channelKeys == nil || channelKeys.Channel != header.Channel {
		return Message{}, errors.New("message belongs to a different channel")
	}
	plaintext, err := channelKeys.Decrypt(body)
	if err != nil {
		return Message{}, err
	}
	metadata, payload, err := UnpackBody(header.Kind, plaintext)
	if err != nil {
		return Message{}, err
	}
	return Message{header.ID, header.Channel, header.Sender, header.Recipient, header.Kind,
		header.Created, header.Expires, metadata, payload}, nil
}
