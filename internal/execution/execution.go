package execution

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"c2dip/internal/state"
)

type Outcome struct {
	State  string
	Output []byte
	Code   *int
	Detail string
}

func code(value int) *int { return &value }

func stop(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = command.Process.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(500 * time.Millisecond):
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	<-done
}

func Execute(command string, timeout time.Duration, maxOutput int, cancel <-chan struct{}, cwd string) Outcome {
	select {
	case <-cancel:
		return Outcome{"cancelled", nil, code(130), "cancelled before execution"}
	default:
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = cwd
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	reader, writer, err := os.Pipe()
	if err != nil {
		return Outcome{"failed", nil, code(127), err.Error()}
	}
	cmd.Stdout, cmd.Stderr = writer, writer
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		return Outcome{"failed", nil, code(127), err.Error()}
	}
	writer.Close()
	type chunkResult struct {
		data []byte
		err  error
	}
	chunks := make(chan chunkResult, 1)
	overflow := make(chan struct{}, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(reader, int64(maxOutput)+1))
		reader.Close()
		if len(data) > maxOutput {
			overflow <- struct{}{}
		}
		chunks <- chunkResult{data, err}
	}()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var waitErr error
	select {
	case <-cancel:
		stopRunning(cmd)
		<-wait
		result := <-chunks
		return Outcome{"cancelled", truncate(result.data, maxOutput), code(130), "command cancelled"}
	case <-timer.C:
		stopRunning(cmd)
		<-wait
		result := <-chunks
		return Outcome{"timed_out", truncate(result.data, maxOutput), code(124), fmt.Sprintf("execution exceeded %g seconds", timeout.Seconds())}
	case <-overflow:
		stopRunning(cmd)
		<-wait
		result := <-chunks
		return Outcome{"output_limit", truncate(result.data, maxOutput), code(125), fmt.Sprintf("output exceeded %d bytes; command terminated", maxOutput)}
	case waitErr = <-wait:
	}
	result := <-chunks
	if len(result.data) > maxOutput {
		return Outcome{"output_limit", result.data[:maxOutput], code(125), fmt.Sprintf("output exceeded %d bytes; command terminated", maxOutput)}
	}
	exitCode := 0
	if waitErr != nil {
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			exitCode = exit.ExitCode()
		} else {
			exitCode = 127
		}
	}
	status := "succeeded"
	if exitCode != 0 {
		status = "failed"
	}
	return Outcome{status, result.data, code(exitCode), ""}
}

func stopRunning(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}

func truncate(data []byte, limit int) []byte {
	if len(data) > limit {
		return data[:limit]
	}
	return data
}

type completed struct {
	id      string
	outcome Outcome
}
type Runner struct {
	mu     sync.Mutex
	id     string
	cancel chan struct{}
	done   chan completed
}

func NewRunner() *Runner { return &Runner{done: make(chan completed, 1)} }
func (r *Runner) Start(id, command string, timeout time.Duration, maxOutput int, cwd string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.id != "" {
		return errors.New("a job is already running")
	}
	r.id, r.cancel = id, make(chan struct{})
	go func(cancel <-chan struct{}) {
		r.done <- completed{id, Execute(command, timeout, maxOutput, cancel, cwd)}
	}(r.cancel)
	return nil
}
func (r *Runner) Cancel(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.id != id || r.cancel == nil {
		return false
	}
	select {
	case <-r.cancel:
	default:
		close(r.cancel)
	}
	return true
}
func (r *Runner) Collect() (string, *Outcome) {
	select {
	case result := <-r.done:
		r.mu.Lock()
		r.id, r.cancel = "", nil
		r.mu.Unlock()
		return result.id, &result.outcome
	default:
		return "", nil
	}
}
func (r *Runner) Busy() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.id != "" }
func (r *Runner) Close() {
	r.mu.Lock()
	if r.cancel != nil {
		select {
		case <-r.cancel:
		default:
			close(r.cancel)
		}
	}
	busy := r.id != ""
	r.mu.Unlock()
	if busy {
		result := <-r.done
		r.done <- result
	}
}

func SafeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if index := strings.LastIndex(name, "/"); index >= 0 {
		name = name[index+1:]
	}
	name = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 32 || character == 127 {
			return -1
		}
		return character
	}, name))
	if name == "" || name == "." || name == ".." {
		name = "file"
	}
	if len([]byte(name)) > 200 {
		extension := filepath.Ext(name)
		if len([]byte(extension)) > 16 {
			extension = validPrefix(extension, 16)
		}
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		name = validPrefix(stem, 200-len([]byte(extension))) + extension
	}
	return name
}

func validPrefix(value string, limit int) string {
	raw := []byte(value)
	if len(raw) <= limit {
		return value
	}
	raw = raw[:limit]
	for !utf8.Valid(raw) {
		raw = raw[:len(raw)-1]
	}
	return string(raw)
}

func ReadFile(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("only regular files can be transferred")
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("file exceeds the %d-byte transfer limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("file exceeds the %d-byte transfer limit", limit)
	}
	return data, nil
}

func SaveFile(database *state.State, jobID, name string, data []byte, outputDirectory string) (string, error) {
	directory, err := filepath.Abs(outputDirectory)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	name = SafeName(name)
	job, err := database.Job(jobID)
	if err != nil {
		return "", err
	}
	planned := ""
	if job != nil {
		planned = job.SavePath
	}
	target := filepath.Join(directory, name)
	if planned != "" {
		target = planned
	}
	expected := sha256.Sum256(data)
	if planned != "" {
		if existing, err := ReadFile(target, len(data)); err == nil && sha256.Sum256(existing) == expected {
			os.Remove(filepath.Join(filepath.Dir(target), ".c2dip-"+jobID+".part"))
			return target, nil
		}
	}
	extension := filepath.Ext(name)
	stem := strings.TrimSuffix(name, extension)
	for index := 1; fileExists(target); index++ {
		target = filepath.Join(directory, fmt.Sprintf("%s.%d%s", stem, index, extension))
	}
	if err := database.PlanPath(jobID, target); err != nil {
		return "", err
	}
	temporary := filepath.Join(filepath.Dir(target), ".c2dip-"+jobID+".part")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(temporary)
		return "", err
	}
	defer os.Remove(temporary)
	for index := 1; ; index++ {
		err = os.Link(temporary, target)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		target = filepath.Join(directory, fmt.Sprintf("%s.%d%s", stem, index, extension))
		if err := database.PlanPath(jobID, target); err != nil {
			return "", err
		}
	}
	directoryFile, err := os.Open(filepath.Dir(target))
	if err == nil {
		err = directoryFile.Sync()
		directoryFile.Close()
	}
	return target, err
}

func fileExists(path string) bool { _, err := os.Lstat(path); return err == nil }
