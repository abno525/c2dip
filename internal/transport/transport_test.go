package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRetriesAreBoundedAndReuseIdenticalUpload(t *testing.T) {
	var bodies [][]byte
	var sleeps []time.Duration
	calls := 0
	client := NewForTests("key", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, body)
		if calls == 1 {
			result := response(request, 429, "busy", "")
			result.Header.Set("Retry-After", "2")
			return result, nil
		}
		return response(request, 200, `{"id":"file-test"}`, ""), nil
	})}, 2, func(delay time.Duration) { sleeps = append(sleeps, delay) })
	id, err := client.Upload("test.png", time.Now().Add(time.Hour).Unix())
	if err != nil || id != "file-test" {
		t.Fatalf("%q %v", id, err)
	}
	if calls != 2 || len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("calls=%d sleeps=%v", calls, sleeps)
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("upload changed during retry")
	}
}

func TestAuthenticationFailureIsNotRetried(t *testing.T) {
	calls := 0
	client := NewForTests("key", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return response(request, 401, "invalid key", ""), nil
	})}, 3, func(time.Duration) { t.Fatal("slept") })
	_, err := client.ListFiles()
	var transportError *Error
	if !errors.As(err, &transportError) || transportError.Retryable || calls != 1 {
		t.Fatalf("%v calls=%d", err, calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(request *http.Request, status int, body, location string) *http.Response {
	header := http.Header{}
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func TestRedirectsCannotLeaveDeepSeek(t *testing.T) {
	for _, destination := range []string{"https://example.com/files", "http://api.deepseek.com/files", "https://api.deepseek.com:444/files", "https://api.deepseek.com.example/files", "https://api.deepseek.com@other.example/files"} {
		t.Run(destination, func(t *testing.T) {
			calls := 0
			client := New("test-key")
			client.retries = 0
			client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return response(request, 302, "", destination), nil
			})
			if _, err := client.ListFiles(); err == nil {
				t.Fatal("redirect accepted")
			}
			if calls != 1 {
				t.Fatalf("made %d requests", calls)
			}
		})
	}
}

func TestSameOriginRedirectKeepsAuthorization(t *testing.T) {
	calls := 0
	client := New("test-key")
	client.retries = 0
	client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatal("authorization missing")
		}
		if calls == 1 {
			return response(request, 302, "", "https://api.deepseek.com:443/v1/files"), nil
		}
		return response(request, 200, `{"data":[],"has_more":false}`, ""), nil
	})
	files, err := client.ListFiles()
	if err != nil || len(files) != 0 {
		t.Fatalf("%v %#v", err, files)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestDefaultClientDisablesProxiesAndRestrictsDial(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "http://proxy.example:8080")
	}
	client := New("key")
	httpTransport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	if httpTransport.Proxy != nil {
		t.Fatal("proxy function enabled")
	}
	if _, err := httpTransport.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("foreign destination dialed")
	}
}

func TestAbsoluteAndNetworkPathsAreRejected(t *testing.T) {
	client := NewForTests("key", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) { t.Fatal("request made"); return nil, nil })}, 0, func(time.Duration) {})
	for _, path := range []string{"https://example.com/files", "//example.com/files", "files"} {
		if _, err := client.request("GET", path, nil, nil); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}
