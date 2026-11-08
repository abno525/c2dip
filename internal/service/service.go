package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"c2dip/internal/execution"
	"c2dip/internal/keys"
	"c2dip/internal/protocol"
	"c2dip/internal/state"
	"c2dip/internal/transport"
)

type Service struct {
	Transport              transport.Mailbox
	State                  *state.State
	Keys                   *keys.ChannelKeys
	Channel, Node, Peer    string
	Receiver               bool
	OutDir, CWD            string
	TTL                    int64
	MaxOutput, MaxTransfer int
	ExecTimeout            time.Duration
	Batch                  int
	Clock                  func() time.Time
	Log                    func(string)
	runner                 *execution.Runner
	quotaWarned            bool
}

type Options struct {
	Channel, Node, Peer    string
	Receiver               bool
	OutDir, CWD            string
	TTL                    int64
	MaxOutput, MaxTransfer int
	ExecTimeout            time.Duration
	Batch                  int
	Clock                  func() time.Time
	Log                    func(string)
}

func New(mailbox transport.Mailbox, database *state.State, channelKeys *keys.ChannelKeys, options Options) (*Service, error) {
	if options.Channel == "" {
		options.Channel = "default"
	}
	if options.Node == "" {
		options.Node = "client"
	}
	if options.Peer == "" {
		options.Peer = "receiver"
	}
	var err error
	if options.Channel, err = protocol.NodeName(options.Channel); err != nil {
		return nil, err
	}
	if options.Node, err = protocol.NodeName(options.Node); err != nil {
		return nil, err
	}
	if options.Peer, err = protocol.NodeName(options.Peer); err != nil {
		return nil, err
	}
	role := "client"
	if options.Receiver {
		role = "receiver"
	}
	if channelKeys == nil || channelKeys.Channel != options.Channel || channelKeys.Role != role {
		return nil, errors.New("key bundle must match this endpoint's channel and role")
	}
	if options.TTL == 0 {
		options.TTL = protocol.MinTTL
	}
	if options.MaxOutput == 0 {
		options.MaxOutput = 65536
	}
	if options.MaxTransfer == 0 {
		options.MaxTransfer = 262144
	}
	if options.ExecTimeout == 0 {
		options.ExecTimeout = 300 * time.Second
	}
	if options.Batch == 0 {
		options.Batch = 16
	}
	if options.MaxOutput < 1 || options.MaxOutput > protocol.MaxData || options.MaxTransfer < 1 || options.MaxTransfer > protocol.MaxData {
		return nil, errors.New("data limits must be between 1 byte and 1 MiB")
	}
	if options.ExecTimeout < time.Second || options.ExecTimeout > 86400*time.Second || options.Batch < 1 || options.Batch > 100 {
		return nil, errors.New("invalid execution timeout or upload batch size")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Log == nil {
		options.Log = func(string) {}
	}
	if options.OutDir == "" {
		options.OutDir = "downloads"
	}
	if options.CWD == "" {
		options.CWD, _ = os.Getwd()
	}
	options.OutDir, _ = filepath.Abs(options.OutDir)
	options.CWD, _ = filepath.Abs(options.CWD)
	if err := database.Bind(role, options.Channel, options.Node, channelKeys.Fingerprint()); err != nil {
		return nil, err
	}
	service := &Service{mailbox, database, channelKeys, options.Channel, options.Node, options.Peer,
		options.Receiver, options.OutDir, options.CWD, options.TTL, options.MaxOutput, options.MaxTransfer,
		options.ExecTimeout, options.Batch, options.Clock, options.Log, nil, false}
	if options.Receiver {
		service.runner = execution.NewRunner()
		if err := service.recover(); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func (s *Service) now() float64 { return float64(s.Clock().UnixNano()) / 1e9 }
func (s *Service) newMessage(kind, peer string, metadata map[string]any, payload []byte, id string) (protocol.Message, error) {
	return protocol.NewMessage(s.Channel, s.Node, peer, kind, metadata, payload, s.TTL, s.Clock(), id)
}

func hashID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:16])
}
func (s *Service) replyID(reference string) string {
	return hashID("reply:" + s.Channel + ":" + s.Node + ":" + reference)
}

func (s *Service) Submit(kind string, metadata map[string]any, payload []byte, peer string) (string, error) {
	if kind == "f" && len(payload) > s.MaxTransfer {
		return "", fmt.Errorf("file exceeds the %d-byte transfer limit", s.MaxTransfer)
	}
	if peer == "" {
		peer = s.Peer
	}
	message, err := s.newMessage(kind, peer, metadata, payload, "")
	if err != nil {
		return "", err
	}
	names, err := protocol.Encode(message, s.Keys)
	if err != nil {
		return "", err
	}
	if err := s.State.Enqueue(message, names, kind == "c" || kind == "g" || kind == "f"); err != nil {
		return "", err
	}
	s.Log(fmt.Sprintf("[%s] queued %d bytes in %d files", message.ID, len(payload), len(names)))
	return message.ID, nil
}

func (s *Service) ack(message protocol.Message) error {
	if message.Kind == "a" || message.Expires <= s.Clock().Unix() {
		return nil
	}
	id := hashID("ack:" + s.Channel + ":" + s.Node + ":" + message.ID)
	ack, err := protocol.NewMessage(s.Channel, s.Node, message.Sender, "a", map[string]any{"ref": message.ID}, nil,
		message.Expires-message.Created, time.Unix(message.Created, 0), id)
	if err != nil {
		return err
	}
	existing, err := s.State.OutMessage(id)
	if err != nil {
		return err
	}
	var names []string
	if existing != nil {
		ack = *existing
	} else {
		names, err = protocol.Encode(ack, s.Keys)
		if err != nil {
			return err
		}
	}
	return s.State.EnsureAck(ack, names, s.now())
}

func shortText(value any, limit int) string {
	raw := []byte(strings.ReplaceAll(fmt.Sprint(value), "\x00", ""))
	if len(raw) > limit {
		raw = raw[:limit]
		for !utf8.Valid(raw) {
			raw = raw[:len(raw)-1]
		}
	}
	return string(raw)
}

func (s *Service) result(request protocol.Message, outcome execution.Outcome, job, path string) (protocol.Message, error) {
	metadata := map[string]any{"reply_to": request.ID, "state": outcome.State, "detail": shortText(outcome.Detail, 900), "code": nil}
	if outcome.Code != nil {
		metadata["code"] = *outcome.Code
	}
	if job != "" {
		metadata["job"] = job
	}
	if path != "" {
		metadata["path"] = shortText(path, 2000)
	}
	return s.newMessage("r", request.Sender, metadata, outcome.Output, s.replyID(request.ID))
}

func intCode(value int) *int { return &value }

func (s *Service) finish(jobID string, outcome execution.Outcome, path string, reply *protocol.Message) error {
	request, err := s.State.Incoming(jobID)
	if err != nil {
		return err
	}
	if request == nil {
		return errors.New("incoming job message is missing")
	}
	response := protocol.Message{}
	if reply != nil {
		response = *reply
	} else {
		response, err = s.result(*request, outcome, "", path)
		if err != nil {
			return err
		}
	}
	names, err := protocol.Encode(response, s.Keys)
	if err != nil {
		outcome = execution.Outcome{State: "output_limit", Output: truncate(outcome.Output, 65536), Code: intCode(125), Detail: "result exceeded the transport limit; output truncated"}
		response, err = s.result(*request, outcome, "", "")
		if err != nil {
			return err
		}
		names, err = protocol.Encode(response, s.Keys)
		if err != nil {
			return err
		}
	}
	if err := s.State.Finish(jobID, outcome.State, outcome.Output, outcome.Code, shortText(outcome.Detail, 900), s.now(), &response, names, path); err != nil {
		return err
	}
	s.Log("[" + jobID + "] " + outcome.State + func() string {
		if outcome.Detail != "" {
			return ": " + outcome.Detail
		}
		return ""
	}())
	return nil
}

func truncate(data []byte, limit int) []byte {
	if len(data) > limit {
		return data[:limit]
	}
	return data
}

func (s *Service) recover() error {
	jobs, err := s.State.Jobs("inbound", map[string]bool{"running": true})
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.Kind == "f" || job.Kind == "g" {
			if err := s.State.RecoverTransfer(job.ID); err != nil {
				return err
			}
		} else if err := s.finish(job.ID, execution.Outcome{State: "uncertain", Detail: "receiver stopped while this command was running; outcome unknown; command was not rerun"}, "", nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) collect() (int, error) {
	if s.runner == nil {
		return 0, nil
	}
	id, outcome := s.runner.Collect()
	if outcome == nil {
		return 0, nil
	}
	return 1, s.finish(id, *outcome, "", nil)
}

func (s *Service) response(message protocol.Message) error {
	reference, _ := message.Metadata["reply_to"].(string)
	request, err := s.State.OutMessage(reference)
	if err != nil {
		return err
	}
	if request == nil || request.Recipient != message.Sender || !strings.Contains("cfgsk", request.Kind) {
		return s.State.Handled(message.ID)
	}
	job, err := s.State.Job(reference)
	if err != nil {
		return err
	}
	if message.Kind == "f" {
		_, hasReply := message.Metadata["reply_to"]
		if request.Kind != "g" || job == nil || !hasReply {
			return s.State.Handled(message.ID)
		}
		if !protocol.IsTerminal(job.State) {
			if len(message.Payload) > s.MaxTransfer {
				return s.State.Finish(reference, "failed", nil, intCode(1), fmt.Sprintf("download exceeds the %d-byte transfer limit", s.MaxTransfer), s.now(), nil, nil, "")
			}
			if _, err := s.State.Start(reference, s.now()); err != nil {
				return err
			}
			name, _ := message.Metadata["name"].(string)
			path, saveErr := execution.SaveFile(s.State, reference, name, message.Payload, s.OutDir)
			if saveErr != nil {
				if err := s.State.Finish(reference, "failed", nil, intCode(1), shortText(saveErr, 900), s.now(), nil, nil, ""); err != nil {
					return err
				}
			} else {
				if err := s.State.Finish(reference, "succeeded", nil, intCode(0), "file received", s.now(), nil, nil, path); err != nil {
					return err
				}
				s.Log(fmt.Sprintf("[%s] received %d bytes: %s", reference, len(message.Payload), path))
			}
		}
	} else if request.Kind == "c" || request.Kind == "f" || request.Kind == "g" {
		stateName, _ := message.Metadata["state"].(string)
		if !protocol.IsTerminal(stateName) {
			return s.State.Handled(message.ID)
		}
		if job != nil && !protocol.IsTerminal(job.State) {
			outcome := execution.Outcome{State: stateName, Output: message.Payload, Detail: anyString(message.Metadata["detail"])}
			if code, ok := metadataInt(message.Metadata["code"]); ok {
				outcome.Code = &code
			}
			if len(outcome.Output) > s.MaxOutput {
				outcome = execution.Outcome{State: "output_limit", Output: outcome.Output[:s.MaxOutput], Code: intCode(125), Detail: "result exceeded the client output limit"}
			}
			path, _ := message.Metadata["path"].(string)
			if err := s.State.Finish(reference, outcome.State, outcome.Output, outcome.Code, outcome.Detail, s.now(), nil, nil, path); err != nil {
				return err
			}
		}
	}
	return s.State.SaveResponse(message, reference)
}

func anyString(value any) string { result, _ := value.(string); return result }
func metadataInt(value any) (int, bool) {
	switch item := value.(type) {
	case int:
		return item, true
	case int64:
		return int(item), true
	case float64:
		return int(item), true
	case interface{ Int64() (int64, error) }:
		result, err := item.Int64()
		return int(result), err == nil
	}
	return 0, false
}

func (s *Service) control(message protocol.Message) error {
	if existing, err := s.State.OutMessage(s.replyID(message.ID)); err != nil {
		return err
	} else if existing != nil {
		return s.State.Handled(message.ID)
	}
	target, _ := message.Metadata["job"].(string)
	job, err := s.State.Job(target)
	if err != nil {
		return err
	}
	var outcome execution.Outcome
	if job == nil || job.Direction != "inbound" || job.Peer != message.Sender {
		outcome = execution.Outcome{State: "not_found", Detail: "job not found for this sender"}
	} else if message.Kind == "k" && job.State == "queued" {
		outcome = execution.Outcome{State: "cancelled", Code: intCode(130), Detail: "cancelled before execution"}
		if err := s.finish(target, outcome, "", nil); err != nil {
			return err
		}
	} else if message.Kind == "k" && s.runner.Cancel(target) {
		outcome = execution.Outcome{State: "cancel_requested", Detail: "cancellation requested"}
	} else {
		output := []byte(nil)
		if message.Kind == "s" {
			requested, _ := message.Metadata["output"].(bool)
			if requested {
				output = job.Output
			}
		}
		outcome = execution.Outcome{State: job.State, Output: output, Code: job.Code, Detail: job.Detail}
	}
	path := ""
	if job != nil {
		path = job.SavePath
	}
	reply, err := s.result(message, outcome, target, path)
	if err != nil {
		return err
	}
	names, err := protocol.Encode(reply, s.Keys)
	if err != nil {
		return err
	}
	if err := s.State.Enqueue(reply, names, false); err != nil {
		return err
	}
	return s.State.Handled(message.ID)
}

func (s *Service) handle(message protocol.Message) error {
	if err := s.ack(message); err != nil {
		return err
	}
	if message.Kind == "a" {
		reference, _ := message.Metadata["ref"].(string)
		if err := s.State.Acknowledge(reference, message.Sender); err != nil {
			return err
		}
		return s.State.Handled(message.ID)
	}
	if message.Kind == "r" || message.Kind == "f" && message.Metadata["reply_to"] != nil {
		return s.response(message)
	}
	if s.Receiver && strings.Contains("cgf", message.Kind) {
		return s.State.AcceptJob(message)
	}
	if s.Receiver && (message.Kind == "s" || message.Kind == "k") {
		return s.control(message)
	}
	return s.State.Handled(message.ID)
}

func (s *Service) startJobs() (int, error) {
	if !s.Receiver {
		return 0, nil
	}
	jobs, err := s.State.Jobs("inbound", map[string]bool{"queued": true})
	if err != nil {
		return 0, err
	}
	if len(jobs) > 16 {
		jobs = jobs[:16]
	}
	activity := 0
	for _, job := range jobs {
		request, err := s.State.Incoming(job.ID)
		if err != nil {
			return activity, err
		}
		if request == nil {
			continue
		}
		if request.Expires <= s.Clock().Unix() {
			if err := s.finish(job.ID, execution.Outcome{State: "expired", Detail: "job expired before execution"}, "", nil); err != nil {
				return activity, err
			}
			activity++
			continue
		}
		if job.Kind == "c" && s.runner.Busy() {
			continue
		}
		started, err := s.State.Start(job.ID, s.now())
		if err != nil {
			return activity, err
		}
		if !started {
			continue
		}
		activity++
		if job.Kind == "c" {
			timeout, _ := metadataInt(request.Metadata["timeout"])
			duration := time.Duration(timeout) * time.Second
			if duration > s.ExecTimeout {
				duration = s.ExecTimeout
			}
			if err := s.runner.Start(job.ID, string(request.Payload), duration, s.MaxOutput, s.CWD); err != nil {
				return activity, err
			}
			s.Log("[" + job.ID + "] running")
			continue
		}
		if job.Kind == "f" {
			if len(request.Payload) > s.MaxTransfer {
				err = fmt.Errorf("upload exceeds the %d-byte transfer limit", s.MaxTransfer)
			} else {
				name, _ := request.Metadata["name"].(string)
				var path string
				path, err = execution.SaveFile(s.State, job.ID, name, request.Payload, s.OutDir)
				if err == nil {
					err = s.finish(job.ID, execution.Outcome{State: "succeeded", Code: intCode(0), Detail: "file saved"}, path, nil)
				}
			}
		} else {
			path := string(request.Payload)
			if !filepath.IsAbs(path) {
				path = filepath.Join(s.CWD, path)
			}
			var data []byte
			data, err = execution.ReadFile(path, s.MaxTransfer)
			if err == nil {
				reply, replyErr := s.newMessage("f", request.Sender, map[string]any{"name": execution.SafeName(filepath.Base(path)), "reply_to": request.ID}, data, s.replyID(request.ID))
				if replyErr != nil {
					err = replyErr
				} else if _, replyErr = protocol.Encode(reply, s.Keys); replyErr != nil {
					err = replyErr
				} else {
					err = s.finish(job.ID, execution.Outcome{State: "succeeded", Code: intCode(0), Detail: fmt.Sprintf("sent %d bytes", len(data))}, "", &reply)
				}
			}
		}
		if err != nil {
			if finishErr := s.finish(job.ID, execution.Outcome{State: "failed", Code: intCode(1), Detail: shortText(err, 900)}, "", nil); finishErr != nil {
				return activity, finishErr
			}
		}
	}
	return activity, nil
}

func (s *Service) Tick() (int, error) {
	acquired, unlock := s.State.AcquirePoll()
	if !acquired {
		return 0, nil
	}
	defer unlock()
	return s.tick()
}

func (s *Service) tick() (int, error) {
	activity, err := s.collect()
	if err != nil {
		return activity, err
	}
	files, err := s.Transport.ListFiles()
	if err != nil {
		return activity, err
	}
	rejected := 0
	for _, file := range files {
		if file.ID == "" {
			continue
		}
		frame, frameErr := protocol.DecodeFrame(file.Filename, s.Keys, s.Channel, s.Node, s.Clock(), true, false)
		if frameErr != nil {
			rejected++
			continue
		}
		if frame == nil {
			continue
		}
		if frame.Header.Expires <= s.Clock().Unix() {
			if err := s.State.Discard(file.ID); err != nil {
				return activity, err
			}
			continue
		}
		message, err := s.State.Ingest(*frame, file.ID, s.Keys)
		if err != nil {
			rejected++
			continue
		}
		if message != nil {
			if err := s.ack(*message); err != nil {
				return activity, err
			}
		}
		activity++
	}
	if rejected != 0 {
		s.Log(fmt.Sprintf("ignored %d invalid or unauthenticated envelope(s)", rejected))
	}
	ready, err := s.State.Ready()
	if err != nil {
		return activity, err
	}
	for _, message := range ready {
		if err := s.handle(message); err != nil {
			return activity, err
		}
	}
	collected, err := s.collect()
	if err != nil {
		return activity, err
	}
	started, err := s.startJobs()
	if err != nil {
		return activity, err
	}
	activity += collected + started
	if err := s.State.Prepare(s.now()); err != nil {
		return activity, err
	}
	remaining := len(files)
	listed := map[string]bool{}
	for _, file := range files {
		listed[file.ID] = true
	}
	garbage, err := s.State.Garbage()
	if err != nil {
		return activity, err
	}
	for _, id := range garbage {
		if err := s.Transport.Delete(id); err != nil {
			return activity, err
		}
		if err := s.State.Deleted(id); err != nil {
			return activity, err
		}
		if listed[id] {
			remaining--
			delete(listed, id)
		}
		activity++
	}
	parts, err := s.State.PendingParts(s.Batch)
	if err != nil {
		return activity, err
	}
	progressed := map[string]bool{}
	for _, part := range parts {
		if part.Expires <= s.Clock().Unix() {
			if err := s.State.Prepare(s.now()); err != nil {
				return activity, err
			}
			continue
		}
		fields := strings.Split(part.Name, ".")
		kind := fields[5]
		limit := transport.FileQuota - 64
		if strings.Contains("arsk", kind) {
			limit = transport.FileQuota
		}
		if remaining >= limit {
			if !s.quotaWarned {
				s.Log("file quota nearly full; pending uploads will resume when space is available")
				s.quotaWarned = true
			}
			break
		}
		s.quotaWarned = false
		if _, err := s.Transport.Upload(part.Name, part.Expires); err != nil {
			return activity, err
		}
		if err := s.State.Sent(part.ID, part.Seq, s.now()); err != nil {
			return activity, err
		}
		progressed[part.ID] = true
		remaining++
		activity++
	}
	for id := range progressed {
		message, err := s.State.OutMessage(id)
		if err != nil {
			return activity, err
		}
		if message != nil && message.Kind != "a" {
			delivery, err := s.State.Delivery(id)
			if err != nil {
				return activity, err
			}
			s.Log(fmt.Sprintf("[%s] uploaded %d/%d files", id, delivery.Sent, delivery.Total))
		}
	}
	return activity, nil
}

func (s *Service) Busy() (bool, error) {
	jobs, err := s.State.Jobs("inbound", map[string]bool{"queued": true, "running": true})
	if err != nil {
		return false, err
	}
	unsent, err := s.State.Unsent()
	return s.runner != nil && s.runner.Busy() || len(jobs) > 0 || unsent > 0, err
}
func (s *Service) Close() error {
	if s.runner != nil {
		s.runner.Close()
		_, err := s.collect()
		return err
	}
	return nil
}
