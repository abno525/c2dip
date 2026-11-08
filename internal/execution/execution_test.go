package execution

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecutionLimitsCancellationAndTimeout(t *testing.T) {
	cancel := make(chan struct{})
	outcome := Execute("printf hello; exit 7", time.Second, 100, cancel, t.TempDir())
	if outcome.State != "failed" || string(outcome.Output) != "hello" || outcome.Code == nil || *outcome.Code != 7 {
		t.Fatalf("%+v", outcome)
	}
	outcome = Execute("yes x", time.Second, 128, make(chan struct{}), t.TempDir())
	if outcome.State != "output_limit" || len(outcome.Output) != 128 {
		t.Fatalf("%+v", outcome)
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "marker")
	outcome = Execute("printf started; sleep 5; touch "+marker, 100*time.Millisecond, 100, make(chan struct{}), directory)
	if outcome.State != "timed_out" || string(outcome.Output) != "started" {
		t.Fatalf("%+v", outcome)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("child survived timeout")
	}
	cancelledMarker := filepath.Join(directory, "cancelled")
	cancelRun := make(chan struct{})
	cancelResult := make(chan Outcome, 1)
	go func() {
		cancelResult <- Execute("printf running; sleep 5; touch "+cancelledMarker, 10*time.Second, 100, cancelRun, directory)
	}()
	time.Sleep(100 * time.Millisecond)
	close(cancelRun)
	outcome = <-cancelResult
	if outcome.State != "cancelled" || string(outcome.Output) != "running" {
		t.Fatalf("%+v", outcome)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(cancelledMarker); !os.IsNotExist(err) {
		t.Fatal("child survived cancellation")
	}
}
