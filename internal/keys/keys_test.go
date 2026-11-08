package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptionSigningIsolationAndBundles(t *testing.T) {
	client, receiver, err := GeneratePair("lab")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*ChannelKeys{{client, receiver}, {receiver, client}} {
		ciphertext, err := pair[0].Encrypt([]byte("private message"))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := pair[1].Decrypt(ciphertext)
		if err != nil || string(plaintext) != "private message" {
			t.Fatalf("round trip: %q %v", plaintext, err)
		}
		signature := pair[0].Sign(ciphertext)
		if err := pair[1].Verify(ciphertext, signature, false); err != nil {
			t.Fatal(err)
		}
		if _, err := pair[0].Decrypt(ciphertext); err == nil {
			t.Fatal("sender decrypted recipient ciphertext")
		}
		if err := pair[1].Verify(append(ciphertext, 'x'), signature, false); err == nil {
			t.Fatal("tampering accepted")
		}
	}
	other, otherReceiver, _ := GeneratePair("other")
	_ = other
	ciphertext, _ := client.Encrypt([]byte("one only"))
	if _, err := otherReceiver.Decrypt(ciphertext); err == nil {
		t.Fatal("other channel decrypted")
	}

	directory := t.TempDir()
	paths, err := CreateChannel(directory, "saved")
	if err != nil {
		t.Fatal(err)
	}
	for index, path := range paths {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", info.Mode().Perm())
		}
		role := []string{"client", "receiver"}[index]
		if _, err := Load(path, "saved", role); err != nil {
			t.Fatal(err)
		}
	}
	original, _ := os.ReadFile(paths[0])
	if _, err := CreateChannel(directory, "saved"); err == nil {
		t.Fatal("overwrote channel")
	}
	current, _ := os.ReadFile(paths[0])
	if !bytes.Equal(original, current) {
		t.Fatal("bundle changed")
	}
	if _, err := Load(paths[0], "other", ""); err == nil {
		t.Fatal("channel mismatch accepted")
	}
	if _, err := Load(paths[0], "saved", "receiver"); err == nil {
		t.Fatal("role mismatch accepted")
	}
	raw, _ := os.ReadFile(paths[0])
	duplicate := bytes.Replace(raw, []byte(`"version": 1,`), []byte(`"version": 1, "version": 1,`), 1)
	duplicatePath := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicatePath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(duplicatePath, "saved", "client"); err == nil {
		t.Fatal("duplicate field accepted")
	}
	if filepath.Base(paths[0]) != "client.json" {
		t.Fatal(paths[0])
	}
}
