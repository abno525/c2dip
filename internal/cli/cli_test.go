package cli

import (
	"os"
	"path/filepath"
	"testing"

	"c2dip/internal/keys"
)

func TestParsingPreservesCommandsAndInterspersedOptions(t *testing.T) {
	args, err := parse([]string{"send", "--timeout", "10", "--exec-timeout", "3", "--", "printf '%s' hello"})
	if err != nil {
		t.Fatal(err)
	}
	if args.timeout != 10 || args.execTimeout != 3 || len(args.positionals) != 1 || args.positionals[0] != "printf '%s' hello" {
		t.Fatalf("%+v", args)
	}
	args, err = parse([]string{"status", "0123456789abcdef0123456789abcdef", "--output", "--json"})
	if err != nil || !args.output || !args.json || len(args.positionals) != 1 {
		t.Fatalf("%+v %v", args, err)
	}
}

func TestRoleRestrictedEntryPoints(t *testing.T) {
	if code := MainSender([]string{"recv", "--once"}); code != 1 {
		t.Fatalf("sender accepted recv: %d", code)
	}
	directory := t.TempDir()
	paths, err := keys.CreateChannel(directory, "embedded")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if code := MainReceiver([]string{"--version"}, "embedded-api-key", bundle); code != 0 {
		t.Fatalf("receiver version failed: %d", code)
	}
	if code := MainReceiver([]string{"send"}, "embedded-api-key", bundle); code != 1 {
		t.Fatalf("receiver accepted command: %d", code)
	}
	if code := MainReceiver([]string{"--version"}, "", bundle); code != 1 {
		t.Fatalf("receiver accepted missing key: %d", code)
	}
	if code := MainReceiver([]string{"--version"}, "key", []byte("invalid")); code != 1 {
		t.Fatalf("receiver accepted invalid bundle: %d", code)
	}
	if filepath.Base(paths[0]) != "client.json" {
		t.Fatal(paths[0])
	}
}

func TestParsingRejectsUnsafeOrUnboundedOptions(t *testing.T) {
	for _, arguments := range [][]string{{"recv", "--interval", "0"}, {"send", "--timeout", "-1"},
		{"send", "--id", "../escape"}, {"recv", "--ttl", "1"}, {"send", "--max-output", "0"}} {
		if _, err := parse(arguments); err == nil {
			t.Fatalf("accepted %v", arguments)
		}
	}
}
