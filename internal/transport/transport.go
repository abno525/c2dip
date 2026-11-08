package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"c2dip/internal/protocol"
)

const (
	Base      = "https://api.deepseek.com"
	FileQuota = 10000
)

var png, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mNgYGAAAAAEAAHI6uv5AAAAAElFTkSuQmCC")

type Error struct {
	Message   string
	Retryable bool
}

func (e *Error) Error() string { return e.Message }

type File struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type Mailbox interface {
	ListFiles() ([]File, error)
	Upload(filename string, expires int64) (string, error)
	Delete(id string) error
}

type DeepSeek struct {
	apiKey  string
	client  *http.Client
	retries int
	sleep   func(time.Duration)
}

func destinationAllowed(destination *url.URL) bool {
	return destination != nil && destination.Scheme == "https" && destination.Hostname() == "api.deepseek.com" &&
		(destination.Port() == "" || destination.Port() == "443") && destination.User == nil
}

func New(apiKey string) *DeepSeek {
	dialer := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	httpTransport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "api.deepseek.com:443" {
				return nil, errors.New("only connections to api.deepseek.com:443 are permitted")
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: httpTransport, Timeout: 20 * time.Second,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if !destinationAllowed(request.URL) {
				return errors.New("redirect outside api.deepseek.com rejected")
			}
			if len(previous) >= 10 {
				return errors.New("too many redirects")
			}
			request.Header.Set("Authorization", "Bearer "+apiKey)
			return nil
		}}
	return &DeepSeek{apiKey: apiKey, client: client, retries: 3, sleep: time.Sleep}
}

func NewForTests(apiKey string, client *http.Client, retries int, sleep func(time.Duration)) *DeepSeek {
	return &DeepSeek{apiKey: apiKey, client: client, retries: retries, sleep: sleep}
}

func (d *DeepSeek) request(method, path string, body []byte, headers map[string]string) (map[string]any, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, &Error{Message: "API path must be relative to api.deepseek.com"}
	}
	destination, err := url.Parse(Base + path)
	if err != nil || !destinationAllowed(destination) {
		return nil, &Error{Message: "only HTTPS connections to api.deepseek.com:443 are permitted"}
	}
	for attempt := 0; attempt <= d.retries; attempt++ {
		request, err := http.NewRequest(method, destination.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+d.apiKey)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := d.client.Do(request)
		if err != nil {
			if attempt < d.retries {
				d.sleep(backoff(attempt, ""))
				continue
			}
			return nil, &Error{Message: fmt.Sprintf("%s %s: %v", method, path, err), Retryable: true}
		}
		limited := io.LimitReader(response.Body, 4*1024*1024+1)
		responseBody, readErr := io.ReadAll(limited)
		response.Body.Close()
		if readErr != nil {
			return nil, &Error{Message: readErr.Error(), Retryable: true}
		}
		if method == http.MethodDelete && response.StatusCode == http.StatusNotFound {
			return map[string]any{"deleted": true}, nil
		}
		retryable := response.StatusCode == 408 || response.StatusCode == 429 || response.StatusCode == 500 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504
		if retryable && attempt < d.retries {
			d.sleep(backoff(attempt, response.Header.Get("Retry-After")))
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			if len(responseBody) > 4096 {
				responseBody = responseBody[:4096]
			}
			return nil, &Error{Message: fmt.Sprintf("%s %s: HTTP %d: %s", method, path, response.StatusCode, responseBody), Retryable: retryable}
		}
		if len(responseBody) == 0 {
			return map[string]any{}, nil
		}
		var result map[string]any
		decoder := json.NewDecoder(bytes.NewReader(responseBody))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil, &Error{Message: "invalid API JSON: " + err.Error()}
		}
		if result == nil {
			return nil, &Error{Message: "API returned an invalid response object"}
		}
		return result, nil
	}
	panic("unreachable")
}

func backoff(attempt int, retryAfter string) time.Duration {
	delay := 500 * time.Millisecond * time.Duration(1<<attempt)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	if seconds, err := strconv.ParseFloat(retryAfter, 64); err == nil && seconds > delay.Seconds() {
		delay = time.Duration(seconds * float64(time.Second))
	} else if parsed, err := http.ParseTime(retryAfter); err == nil && time.Until(parsed) > delay {
		delay = time.Until(parsed)
	}
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	if delay < 0 {
		delay = 0
	}
	return delay
}

func (d *DeepSeek) ListFiles() ([]File, error) {
	var files []File
	cursors := map[string]bool{}
	after := ""
	for {
		query := url.Values{"limit": {"1000"}, "order": {"asc"}}
		if after != "" {
			query.Set("after", after)
		}
		response, err := d.request(http.MethodGet, "/files?"+query.Encode(), nil, nil)
		if err != nil {
			return nil, err
		}
		raw, ok := response["data"].([]any)
		if !ok {
			return nil, &Error{Message: "invalid file listing"}
		}
		page := make([]File, 0, len(raw))
		for _, item := range raw {
			object, ok := item.(map[string]any)
			if !ok {
				return nil, &Error{Message: "invalid file listing"}
			}
			id, _ := object["id"].(string)
			name, _ := object["filename"].(string)
			page = append(page, File{ID: id, Filename: name})
		}
		files = append(files, page...)
		hasMore, _ := response["has_more"].(bool)
		if !hasMore {
			return files, nil
		}
		after, _ = response["last_id"].(string)
		if after == "" && len(page) != 0 {
			after = page[len(page)-1].ID
		}
		if after == "" || cursors[after] {
			return nil, &Error{Message: "file pagination did not advance"}
		}
		cursors[after] = true
	}
}

func (d *DeepSeek) Upload(filename string, expires int64) (string, error) {
	if len(filename) > protocol.MaxName || !isASCII(filename) || strings.ContainsAny(filename, "\r\n\"") {
		return "", &Error{Message: "invalid transport filename"}
	}
	ttl := expires - time.Now().Unix()
	if ttl < protocol.MinTTL {
		ttl = protocol.MinTTL
	}
	if ttl > protocol.MaxTTL {
		ttl = protocol.MaxTTL
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("purpose", "user_data")
	_ = writer.WriteField("expires_after[anchor]", "created_at")
	_ = writer.WriteField("expires_after[seconds]", strconv.FormatInt(ttl, 10))
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename))
	header.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(header)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(png); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	response, err := d.request(http.MethodPost, "/files", body.Bytes(), map[string]string{"Content-Type": writer.FormDataContentType()})
	if err != nil {
		return "", err
	}
	id, ok := response["id"].(string)
	if !ok || id == "" {
		return "", &Error{Message: "upload response has no file ID"}
	}
	return id, nil
}

func (d *DeepSeek) Delete(id string) error {
	_, err := d.request(http.MethodDelete, "/files/"+url.PathEscape(id), nil, nil)
	return err
}

func isASCII(value string) bool {
	for _, character := range []byte(value) {
		if character >= 128 {
			return false
		}
	}
	return true
}
