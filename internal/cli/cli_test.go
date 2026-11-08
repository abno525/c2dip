package cli

import "testing"

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

func TestParsingRejectsUnsafeOrUnboundedOptions(t *testing.T) {
	for _, arguments := range [][]string{{"recv", "--interval", "0"}, {"send", "--timeout", "-1"},
		{"send", "--id", "../escape"}, {"recv", "--ttl", "1"}, {"send", "--max-output", "0"}} {
		if _, err := parse(arguments); err == nil {
			t.Fatalf("accepted %v", arguments)
		}
	}
}
