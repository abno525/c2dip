package protocol

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"c2dip/internal/keys"
)

func TestEncryptedFramingRoundTripAndTampering(t *testing.T) {
	client, receiver, _ := keys.GeneratePair("test")
	now := time.Unix(1800000000, 0)
	payload := bytes.Repeat([]byte("sensitive content"), 300)
	message, err := NewMessage("test", "client", "receiver", "f", map[string]any{"name": "private-report.txt"}, payload, MinTTL, now, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Encode(message, client)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Encode(message, client)
	if len(first) < 2 {
		t.Fatal("expected chunks")
	}
	if first[0] == second[0] {
		t.Fatal("encryption was deterministic")
	}
	frames := make([]Frame, 0, len(first))
	ciphertext := []byte{}
	for index := len(first) - 1; index >= 0; index-- {
		frame, err := DecodeFrame(first[index], receiver, "test", "receiver", now, false, false)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, *frame)
		ciphertext = append(ciphertext, frame.Data...)
	}
	if bytes.Contains(ciphertext, []byte("private-report.txt")) || bytes.Contains(ciphertext, []byte("sensitive content")) {
		t.Fatal("plaintext leaked")
	}
	assembled, err := Assemble(frames, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(assembled.Payload, payload) || assembled.Metadata["name"] != "private-report.txt" {
		t.Fatal("message mismatch")
	}
	if _, err := Assemble(frames, client); err == nil {
		t.Fatal("sender decrypted outgoing message")
	}
	fields := strings.Split(first[0], ".")
	fields[2] = "impostor"
	if _, err := DecodeFrame(strings.Join(fields, "."), receiver, "", "", now, false, false); err == nil {
		t.Fatal("tampering accepted")
	}
	_, wrong, _ := keys.GeneratePair("test")
	if _, err := DecodeFrame(first[0], wrong, "", "", now, false, false); err == nil {
		t.Fatal("wrong signature key accepted")
	}
}

func TestStrictBodiesAndRouting(t *testing.T) {
	client, receiver, _ := keys.GeneratePair("test")
	now := time.Unix(1800000000, 0)
	for _, metadata := range []map[string]any{{"timeout": true}, {"timeout": 0}, {"timeout": 1, "extra": 0}} {
		if _, err := NewMessage("test", "client", "receiver", "c", metadata, []byte("true"), MinTTL, now, ""); err == nil {
			t.Fatalf("accepted %#v", metadata)
		}
	}
	header := []byte(`{"timeout":1,"timeout":2}`)
	body := make([]byte, 4+len(header)+4)
	body[3] = byte(len(header))
	copy(body[4:], header)
	copy(body[4+len(header):], "true")
	if _, _, err := UnpackBody("c", body); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
	message, _ := NewMessage("test", "client", "receiver", "c", map[string]any{"timeout": 5}, []byte("true"), MinTTL, now, "")
	names, _ := Encode(message, client)
	if frame, err := DecodeFrame(names[0], receiver, "test", "other", now, false, false); err != nil || frame != nil {
		t.Fatal("recipient filter failed")
	}
	if frame, err := DecodeFrame("c2d2.old.png", receiver, "", "", now, false, false); err != nil || frame != nil {
		t.Fatal("legacy frame accepted")
	}
}
