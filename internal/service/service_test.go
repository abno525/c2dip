package service

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"c2dip/internal/keys"
	"c2dip/internal/state"
	"c2dip/internal/transport"
)

type memoryMailbox struct {
	mu        sync.Mutex
	files     map[string]transport.File
	counter   int
	uploads   []string
	ambiguous bool
}

func (m *memoryMailbox) ListFiles() ([]transport.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]transport.File, 0, len(m.files))
	for _, file := range m.files {
		result = append(result, file)
	}
	slices.Reverse(result)
	return result, nil
}
func (m *memoryMailbox) Upload(name string, expires int64) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	id := fmt.Sprintf("file-%d", m.counter)
	m.files[id] = transport.File{ID: id, Filename: name, ExpiresAt: expires}
	m.uploads = append(m.uploads, name)
	if m.ambiguous {
		m.ambiguous = false
		return "", &transport.Error{Message: "lost after upload", Retryable: true}
	}
	return id, nil
}
func (m *memoryMailbox) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, id)
	return nil
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time                 { return c.now }
func (c *testClock) Advance(duration time.Duration) { c.now = c.now.Add(duration) }

func TestEncryptedCommandAndBidirectionalFiles(t *testing.T) {
	root := t.TempDir()
	mailbox := &memoryMailbox{files: map[string]transport.File{}}
	clock := &testClock{now: time.Unix(1800000000, 0)}
	clientKeys, receiverKeys, _ := keys.GeneratePair("default")
	clientDB, err := state.Open(filepath.Join(root, "client.sqlite3"), false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clientDB.Close()
	receiverDB, err := state.Open(filepath.Join(root, "receiver.sqlite3"), true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer receiverDB.Close()
	clientDir := filepath.Join(root, "client")
	receiverDir := filepath.Join(root, "receiver")
	os.MkdirAll(clientDir, 0o755)
	os.MkdirAll(receiverDir, 0o755)
	client, err := New(mailbox, clientDB, clientKeys, Options{Node: "client", Peer: "receiver", OutDir: filepath.Join(clientDir, "downloads"), CWD: clientDir, Clock: clock.Now, Batch: 100, ExecTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	worker, err := New(mailbox, receiverDB, receiverKeys, Options{Node: "receiver", Peer: "client", Receiver: true, OutDir: receiverDir, CWD: receiverDir, Clock: clock.Now, Batch: 100, ExecTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	drive := func(done func() bool) {
		t.Helper()
		for range 500 {
			if _, err := client.Tick(); err != nil {
				t.Fatal(err)
			}
			if _, err := worker.Tick(); err != nil {
				t.Fatal(err)
			}
			if done() {
				return
			}
			clock.Advance(50 * time.Millisecond)
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatal("services did not settle")
	}
	reference, err := client.Submit("c", map[string]any{"timeout": 5}, []byte("printf go-roundtrip; exit 7"), "")
	if err != nil {
		t.Fatal(err)
	}
	drive(func() bool { response, _ := clientDB.Response(reference); return response != nil })
	job, _ := clientDB.Job(reference)
	if job.State != "failed" || string(job.Output) != "go-roundtrip" || job.Code == nil || *job.Code != 7 {
		t.Fatalf("%+v", job)
	}
	delivery, _ := clientDB.Delivery(reference)
	if delivery.State != "delivered" {
		t.Fatalf("%+v", delivery)
	}
	data := make([]byte, 4096)
	for index := range data {
		data[index] = byte(index)
	}
	upload, err := client.Submit("f", map[string]any{"name": "payload.bin"}, data, "")
	if err != nil {
		t.Fatal(err)
	}
	drive(func() bool { response, _ := clientDB.Response(upload); return response != nil })
	saved, err := os.ReadFile(filepath.Join(receiverDir, "payload.bin"))
	if err != nil || !slices.Equal(saved, data) {
		t.Fatalf("upload: %v", err)
	}
	download, err := client.Submit("g", nil, []byte("payload.bin"), "")
	if err != nil {
		t.Fatal(err)
	}
	drive(func() bool { response, _ := clientDB.Response(download); return response != nil })
	downloadJob, _ := clientDB.Job(download)
	received, err := os.ReadFile(downloadJob.SavePath)
	if err != nil || !slices.Equal(received, data) {
		t.Fatalf("download: %v", err)
	}
	for _, name := range mailbox.uploads {
		if len(name) > 500 {
			t.Fatal("oversized filename")
		}
		if contains(name, "go-roundtrip") || contains(name, "payload.bin") {
			t.Fatal("plaintext leaked in filename")
		}
	}
}

func contains(value, needle string) bool {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestAmbiguousUploadReusesCiphertext(t *testing.T) {
	root := t.TempDir()
	mailbox := &memoryMailbox{files: map[string]transport.File{}, ambiguous: true}
	clock := &testClock{now: time.Unix(1800000000, 0)}
	clientKeys, _, _ := keys.GeneratePair("default")
	database, _ := state.Open(filepath.Join(root, "client.sqlite3"), false, false)
	defer database.Close()
	client, err := New(mailbox, database, clientKeys, Options{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reference, err := client.Submit("c", map[string]any{"timeout": 5}, []byte("true"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Tick(); err == nil {
		t.Fatal("expected ambiguous failure")
	}
	first := mailbox.uploads[0]
	if _, err := client.Tick(); err != nil {
		t.Fatal(err)
	}
	if len(mailbox.uploads) < 2 || mailbox.uploads[1] != first {
		t.Fatal("retry changed randomized ciphertext")
	}
	delivery, _ := database.Delivery(reference)
	if delivery.Sent == 0 {
		t.Fatal("retry was not recorded")
	}
}
