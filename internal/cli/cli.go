package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"c2dip/internal/execution"
	"c2dip/internal/keys"
	"c2dip/internal/protocol"
	"c2dip/internal/service"
	"c2dip/internal/state"
	"c2dip/internal/transport"
	"github.com/google/shlex"
	"github.com/spf13/pflag"
)

const Version = "3.0.0"

var rootDirectory = func() string {
	executable, err := os.Executable()
	if err != nil {
		directory, _ := os.Getwd()
		return directory
	}
	return filepath.Dir(executable)
}()

type arguments struct {
	action, channel, node, peer, stateDir, keyFile, out string
	timeout, interval, idleTimeout                      float64
	ttl                                                 int64
	execTimeout, maxOutput, maxTransfer, batch          int
	quiet, noWait, once, json, output                   bool
	wait                                                float64
	positionals                                         []string
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "c2dip - encrypted jobs over the DeepSeek Files API")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Usage: c2dip COMMAND [OPTIONS]")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Commands: init, send, recv, upload, download, status, cancel, jobs, resume, list")
	fmt.Fprintln(writer, "Run 'c2dip COMMAND --help' for command options.")
}

func parse(argv []string) (*arguments, error) {
	if len(argv) == 0 || argv[0] == "--help" || argv[0] == "-h" {
		usage(os.Stdout)
		return nil, pflag.ErrHelp
	}
	if argv[0] == "--version" {
		fmt.Fprintln(os.Stdout, Version)
		return nil, pflag.ErrHelp
	}
	valid := map[string]bool{"init": true, "send": true, "recv": true, "upload": true, "download": true, "status": true, "cancel": true, "jobs": true, "resume": true, "list": true}
	if !valid[argv[0]] {
		return nil, fmt.Errorf("unknown command %q", argv[0])
	}
	result := &arguments{action: argv[0]}
	stateDefault := os.Getenv("C2DIP_STATE_DIR")
	if stateDefault == "" {
		stateDefault = filepath.Join(rootDirectory, ".c2dip")
	}
	set := pflag.NewFlagSet(result.action, pflag.ContinueOnError)
	set.SetInterspersed(true)
	set.SetOutput(os.Stdout)
	set.StringVar(&result.channel, "channel", envDefault("C2DIP_CHANNEL", "default"), "channel name")
	if result.action == "init" {
		set.StringVar(&result.stateDir, "key-dir", filepath.Join(stateDefault, "keys"), "parent directory for channel bundles")
	} else {
		set.StringVar(&result.node, "id", "", "stable local node ID")
		set.StringVar(&result.peer, "peer", "", "recipient node ID")
		set.StringVar(&result.stateDir, "state-dir", stateDefault, "state directory")
		set.StringVar(&result.keyFile, "key-file", "", "endpoint key bundle")
		outDefault := filepath.Join(rootDirectory, "downloads")
		if result.action == "recv" {
			outDefault, _ = os.Getwd()
		}
		set.StringVar(&result.out, "out", outDefault, "received-file directory")
		set.Float64Var(&result.timeout, "timeout", 300, "client wait timeout; 0 waits indefinitely")
		receiverInterval := 0.5
		if result.action == "recv" {
			receiverInterval = 1
		}
		set.Float64Var(&result.interval, "interval", receiverInterval, "polling interval")
		set.Int64Var(&result.ttl, "ttl", protocol.MinTTL, "message lifetime in seconds")
		execDefault := 60
		if result.action == "recv" {
			execDefault = 300
		}
		set.IntVar(&result.execTimeout, "exec-timeout", execDefault, "command runtime limit")
		set.IntVar(&result.maxOutput, "max-output", 65536, "maximum command output bytes")
		set.IntVar(&result.maxTransfer, "max-transfer", 262144, "maximum transfer bytes")
		set.IntVar(&result.batch, "batch", 16, "uploads per polling cycle")
		set.BoolVar(&result.quiet, "quiet", false, "suppress progress")
	}
	switch result.action {
	case "send", "upload":
		set.BoolVar(&result.noWait, "no-wait", false, "return after uploading")
	case "recv":
		set.BoolVar(&result.once, "once", false, "drain work and exit")
		set.Float64Var(&result.idleTimeout, "idle-timeout", 0, "idle seconds before exit")
	case "download":
		set.Float64Var(&result.wait, "wait", 0, "seconds to collect downloads")
	case "status":
		set.BoolVar(&result.output, "output", false, "retrieve output")
		set.BoolVar(&result.json, "json", false, "JSON output")
	case "cancel", "jobs", "list":
		set.BoolVar(&result.json, "json", false, "JSON output")
	}
	if err := set.Parse(argv[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, pflag.ErrHelp
		}
		return nil, err
	}
	result.positionals = set.Args()
	if result.action != "init" {
		if result.interval < 0.01 || result.timeout < 0 || result.wait < 0 || result.idleTimeout < 0 {
			return nil, errors.New("timeouts must be nonnegative and interval at least 0.01")
		}
		if result.ttl < protocol.MinTTL || result.ttl > protocol.MaxTTL || result.execTimeout < 1 || result.execTimeout > 86400 || result.maxOutput < 1 || result.maxOutput > protocol.MaxData || result.maxTransfer < 1 || result.maxTransfer > protocol.MaxData || result.batch < 1 || result.batch > 100 {
			return nil, errors.New("numeric option is outside its permitted range")
		}
	}
	if _, err := protocol.NodeName(result.channel); err != nil {
		return nil, err
	}
	if result.node != "" {
		if _, err := protocol.NodeName(result.node); err != nil {
			return nil, err
		}
	}
	if result.peer != "" {
		if _, err := protocol.NodeName(result.peer); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func apiCredential(embedded string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("DEEPSEEK_API_KEY"))
	if apiKey == "" {
		raw, err := os.ReadFile(filepath.Join(rootDirectory, "key.txt"))
		if err == nil {
			apiKey = strings.TrimSpace(string(raw))
		}
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(embedded)
	}
	if apiKey == "" {
		return "", errors.New("missing API key: set DEEPSEEK_API_KEY or create key.txt")
	}
	return apiKey, nil
}

func history(database *state.State, asJSON bool) error {
	jobs, err := database.Jobs("", nil)
	if err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		row := map[string]any{"id": job.ID, "direction": job.Direction, "peer": job.Peer, "kind": job.Kind, "state": job.State, "created": job.Created, "updated": job.Updated, "output_bytes": len(job.Output), "code": job.Code, "detail": job.Detail, "response_id": nullable(job.ResponseID), "save_path": nullable(job.SavePath), "delivery": nil}
		if job.Direction == "outbound" {
			delivery, err := database.Delivery(job.ID)
			if err != nil {
				return err
			}
			row["delivery"] = delivery
		}
		rows = append(rows, row)
	}
	if asJSON {
		raw, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("no jobs")
		return nil
	}
	for _, row := range rows {
		suffix := ""
		if delivery, ok := row["delivery"].(*state.Delivery); ok && delivery != nil {
			suffix = "  delivery=" + delivery.State
		}
		if row["detail"] != "" {
			suffix += "  " + row["detail"].(string)
		}
		fmt.Printf("%s  %s  %s  %s%s\n", row["id"], row["kind"], row["peer"], row["state"], suffix)
	}
	return nil
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func remoteListing(mailbox transport.Mailbox, channelKeys *keys.ChannelKeys, channel string, asJSON bool) error {
	files, err := mailbox.ListFiles()
	if err != nil {
		return err
	}
	groups := map[string]map[string]any{}
	parts := map[string]map[int]bool{}
	for _, file := range files {
		frame, err := protocol.DecodeFrame(file.Filename, channelKeys, channel, "", time.Now(), true, true)
		if err != nil || frame == nil {
			continue
		}
		key := frame.Header.Sender + ":" + frame.Header.ID
		if groups[key] == nil {
			groups[key] = map[string]any{"id": frame.Header.ID, "kind": frame.Header.Kind, "sender": frame.Header.Sender, "recipient": frame.Header.Recipient, "total": frame.Header.Total, "expires": frame.Header.Expires}
			parts[key] = map[int]bool{}
		}
		parts[key][frame.Index] = true
	}
	rows := make([]map[string]any, 0, len(groups))
	for key, row := range groups {
		row["parts"] = len(parts[key])
		rows = append(rows, row)
	}
	if asJSON {
		raw, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("no authenticated v3 messages in this channel")
		return nil
	}
	for _, row := range rows {
		fmt.Printf("%s  %s  %s -> %s  %d/%d\n", row["id"], row["kind"], row["sender"], row["recipient"], row["parts"], row["total"])
	}
	return nil
}

func poll(instance *service.Service) (int, error) {
	activity, err := instance.Tick()
	if transportError := new(transport.Error); errors.As(err, &transportError) && transportError.Retryable {
		instance.Log("API temporarily unavailable; local state retained: " + err.Error())
		return 0, nil
	}
	return activity, err
}

func waitFor(instance *service.Service, reference string, timeout, interval float64, uploadedOnly bool) (*protocol.Message, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(time.Duration(timeout * float64(time.Second)))
	}
	for {
		response, err := instance.State.Response(reference)
		if err != nil {
			return nil, err
		}
		delivery, err := instance.State.Delivery(reference)
		if err != nil {
			return nil, err
		}
		if response != nil || uploadedOnly && delivery != nil && (delivery.State == "waiting" || delivery.State == "delivered") {
			return response, nil
		}
		if delivery != nil && (delivery.State == "failed" || delivery.State == "expired") {
			return nil, fmt.Errorf("%s: delivery %s; inspect jobs/status, or resume an unexpired delivery", reference, delivery.State)
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: wait timed out; state is saved", reference)
		}
		if _, err := poll(instance); err != nil {
			return nil, err
		}
		time.Sleep(time.Duration(interval * float64(time.Second)))
	}
}

func displayJob(instance *service.Service, id string) (int, error) {
	job, err := instance.State.Job(id)
	if err != nil {
		return 1, err
	}
	if job == nil {
		return 1, errors.New("job is not in local history")
	}
	if len(job.Output) > 0 {
		os.Stdout.Write(job.Output)
	}
	if job.SavePath != "" && job.State == "succeeded" {
		fmt.Println(job.SavePath)
	}
	if job.State != "succeeded" {
		suffix := ""
		if job.Code != nil {
			suffix = fmt.Sprintf(" (exit %d)", *job.Code)
		}
		if job.Detail != "" {
			suffix += ": " + job.Detail
		}
		fmt.Fprintf(os.Stderr, "[%s] %s%s\n", id, job.State, suffix)
		if job.Code != nil && *job.Code >= 1 && *job.Code <= 255 {
			return *job.Code, nil
		}
		return 1, nil
	}
	return 0, nil
}

func requestJob(instance *service.Service, args *arguments, kind string, metadata map[string]any, payload []byte, noWait bool) (int, error) {
	reference, err := instance.Submit(kind, metadata, payload, "")
	if err != nil {
		return 1, err
	}
	if _, err = waitFor(instance, reference, args.timeout, args.interval, noWait); err != nil {
		return 1, err
	}
	if noWait {
		fmt.Println(reference)
		return 0, nil
	}
	return displayJob(instance, reference)
}

func control(instance *service.Service, args *arguments, kind, id string) (int, error) {
	metadata := map[string]any{"job": id}
	if kind == "s" {
		metadata["output"] = args.output
	}
	reference, err := instance.Submit(kind, metadata, nil, "")
	if err != nil {
		return 1, err
	}
	response, err := waitFor(instance, reference, args.timeout, args.interval, false)
	if err != nil {
		return 1, err
	}
	if args.json {
		result := map[string]any{}
		for key, value := range response.Metadata {
			result[key] = value
		}
		if args.output {
			result["output"] = string(response.Payload)
		}
		raw, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(raw))
	} else {
		code, _ := metadataInteger(response.Metadata["code"])
		stateName, _ := response.Metadata["state"].(string)
		suffix := ""
		if response.Metadata["code"] != nil {
			suffix = fmt.Sprintf(" (exit %d)", code)
		}
		destination := io.Writer(os.Stdout)
		if args.output {
			destination = os.Stderr
		}
		fmt.Fprintf(destination, "%s: %s%s\n", id, stateName, suffix)
		if detail, _ := response.Metadata["detail"].(string); detail != "" {
			fmt.Fprintln(destination, detail)
		}
		if args.output {
			os.Stdout.Write(response.Payload)
		}
	}
	if response.Metadata["state"] == "not_found" {
		return 1, nil
	}
	return 0, nil
}
func metadataInteger(value any) (int, bool) {
	switch item := value.(type) {
	case int:
		return item, true
	case int64:
		return int(item), true
	case json.Number:
		value, err := item.Int64()
		return int(value), err == nil
	}
	return 0, false
}

func console(instance *service.Service, args *arguments) (int, error) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		if terminal() {
			fmt.Print("> ")
		}
		if !scanner.Scan() {
			return 0, scanner.Err()
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "exit" || trimmed == "quit" || trimmed == ":q" {
			return 0, nil
		}
		words, splitErr := shlex.Split(trimmed)
		if splitErr != nil {
			fmt.Fprintln(os.Stderr, "error:", splitErr)
			continue
		}
		if len(words) == 2 && (words[0] == "status" || words[0] == "cancel") {
			id, err := protocol.Identifier(words[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				continue
			}
			kind := "s"
			if words[0] == "cancel" {
				kind = "k"
			}
			if _, err := control(instance, args, kind, id); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			continue
		}
		if len(words) == 2 && words[0] == "upload" {
			data, err := execution.ReadFile(words[1], instance.MaxTransfer)
			if err == nil {
				_, err = requestJob(instance, args, "f", map[string]any{"name": execution.SafeName(words[1])}, data, false)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			continue
		}
		if len(words) == 2 && words[0] == "download" {
			if _, err := requestJob(instance, args, "g", nil, []byte(words[1]), false); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			continue
		}
		if len(words) > 0 && (words[0] == "status" || words[0] == "cancel" || words[0] == "upload" || words[0] == "download") {
			fmt.Fprintf(os.Stderr, "error: usage: %s <path or job ID>\n", words[0])
			continue
		}
		if trimmed == "jobs" {
			_ = history(instance.State, false)
			continue
		}
		code, err := requestJob(instance, args, "c", map[string]any{"timeout": args.execTimeout}, []byte(line), args.noWait)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		} else if code != 0 {
			fmt.Fprintf(os.Stderr, "exit %d\n", code)
		}
	}
}
func terminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && (info.Mode()&os.ModeCharDevice) != 0
}

func receive(instance *service.Service, args *arguments, signals <-chan os.Signal) (int, error) {
	last := time.Now()
	delay := args.interval
	for {
		select {
		case <-signals:
			return 130, nil
		default:
		}
		activity, err := poll(instance)
		if err != nil {
			return 1, err
		}
		busy, err := instance.Busy()
		if err != nil {
			return 1, err
		}
		if activity > 0 || busy {
			last = time.Now()
			delay = args.interval
		} else {
			delay = min(delay*1.5, max(5, args.interval))
		}
		if args.once && !busy {
			return 0, nil
		}
		if args.idleTimeout > 0 && time.Since(last) >= time.Duration(args.idleTimeout*float64(time.Second)) {
			return 0, nil
		}
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

func run(instance *service.Service, args *arguments, signals <-chan os.Signal) (int, error) {
	switch args.action {
	case "recv":
		return receive(instance, args, signals)
	case "send":
		if len(args.positionals) == 0 {
			return console(instance, args)
		}
		return requestJob(instance, args, "c", map[string]any{"timeout": args.execTimeout}, []byte(strings.Join(args.positionals, " ")), args.noWait)
	case "upload":
		if len(args.positionals) != 1 {
			return 1, errors.New("upload requires one path")
		}
		data, err := execution.ReadFile(args.positionals[0], instance.MaxTransfer)
		if err != nil {
			return 1, err
		}
		return requestJob(instance, args, "f", map[string]any{"name": execution.SafeName(args.positionals[0])}, data, args.noWait)
	case "download":
		if len(args.positionals) > 1 {
			return 1, errors.New("download accepts at most one path")
		}
		if len(args.positionals) == 1 {
			return requestJob(instance, args, "g", nil, []byte(args.positionals[0]), false)
		}
		printed := map[string]bool{}
		existing, _ := instance.State.Jobs("outbound", map[string]bool{"succeeded": true})
		for _, job := range existing {
			printed[job.ID] = true
		}
		deadline := time.Now().Add(time.Duration(args.wait * float64(time.Second)))
		for {
			if _, err := poll(instance); err != nil {
				return 1, err
			}
			jobs, err := instance.State.Jobs("outbound", map[string]bool{"succeeded": true})
			if err != nil {
				return 1, err
			}
			for _, job := range jobs {
				if job.Kind == "g" && !printed[job.ID] {
					fmt.Println(job.SavePath)
					printed[job.ID] = true
				}
			}
			if !time.Now().Before(deadline) {
				return 0, nil
			}
			time.Sleep(time.Duration(args.interval * float64(time.Second)))
		}
	case "status", "cancel":
		if len(args.positionals) != 1 {
			return 1, errors.New(args.action + " requires one job ID")
		}
		id, err := protocol.Identifier(args.positionals[0])
		if err != nil {
			return 1, err
		}
		kind := "s"
		if args.action == "cancel" {
			kind = "k"
		}
		return control(instance, args, kind, id)
	case "resume":
		if len(args.positionals) > 1 {
			return 1, errors.New("resume accepts at most one job ID")
		}
		if err := instance.State.Retry(float64(time.Now().UnixNano()) / 1e9); err != nil {
			return 1, err
		}
		if len(args.positionals) == 1 {
			id, err := protocol.Identifier(args.positionals[0])
			if err != nil {
				return 1, err
			}
			if _, err := waitFor(instance, id, args.timeout, args.interval, false); err != nil {
				return 1, err
			}
			return displayJob(instance, id)
		}
		var deadline time.Time
		if args.timeout > 0 {
			deadline = time.Now().Add(time.Duration(args.timeout * float64(time.Second)))
		}
		for {
			pending, err := instance.State.Pending()
			if err != nil {
				return 1, err
			}
			if pending == 0 {
				return 0, history(instance.State, false)
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				return 1, errors.New("resume timed out; remaining deliveries are saved")
			}
			if _, err := poll(instance); err != nil {
				return 1, err
			}
			time.Sleep(time.Duration(args.interval * float64(time.Second)))
		}
	}
	return 1, errors.New("unknown action")
}

type runtimeConfig struct {
	mode           string
	embeddedAPIKey string
	embeddedKeys   *keys.ChannelKeys
}

func Main(argv []string) int { return mainWithConfig(argv, runtimeConfig{}) }

func MainSender(argv []string) int { return mainWithConfig(argv, runtimeConfig{mode: "sender"}) }

func MainReceiver(argv []string, embeddedAPIKey string, bundle []byte) int {
	channelKeys, err := keys.Parse(bundle, "", "receiver")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: invalid embedded receiver bundle:", err)
		return 1
	}
	if strings.TrimSpace(embeddedAPIKey) == "" {
		fmt.Fprintln(os.Stderr, "error: receiver binary has no embedded DeepSeek API key")
		return 1
	}
	if len(argv) == 1 && argv[0] == "--version" {
		fmt.Fprintln(os.Stdout, Version)
		return 0
	}
	arguments := append([]string{"recv", "--channel", channelKeys.Channel}, argv...)
	return mainWithConfig(arguments, runtimeConfig{mode: "receiver", embeddedAPIKey: embeddedAPIKey, embeddedKeys: channelKeys})
}

func mainWithConfig(argv []string, config runtimeConfig) int {
	args, err := parse(argv)
	if errors.Is(err, pflag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if config.mode == "sender" && args.action == "recv" {
		fmt.Fprintln(os.Stderr, "error: c2dip-sender cannot run receiver mode")
		return 1
	}
	if config.mode == "receiver" && (args.action != "recv" || len(args.positionals) != 0) {
		fmt.Fprintln(os.Stderr, "error: c2dip-receiver accepts receiver options only")
		return 1
	}
	if args.action == "init" {
		paths, err := keys.CreateChannel(args.stateDir, args.channel)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Client bundle: %s\nReceiver bundle: %s\nGive each endpoint only its own bundle; peer public keys are already included.\n", paths[0], paths[1])
		return 0
	}
	receiver := args.action == "recv"
	if args.node == "" {
		if receiver {
			args.node = "receiver"
		} else {
			args.node = "client"
		}
	}
	if args.peer == "" {
		if receiver {
			args.peer = "client"
		} else {
			args.peer = "receiver"
		}
	}
	if _, err := protocol.NodeName(args.node); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if _, err := protocol.NodeName(args.peer); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if args.node == args.peer {
		fmt.Fprintln(os.Stderr, "error: local --id and --peer must differ")
		return 1
	}
	path := filepath.Join(args.stateDir, "v3", args.channel, args.node+".sqlite3")
	if args.action == "jobs" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if args.json {
				fmt.Println("[]")
			} else {
				fmt.Println("no jobs")
			}
			return 0
		}
		database, err := state.Open(path, false, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer database.Close()
		if err := history(database, args.json); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}
	role := "client"
	if receiver {
		role = "receiver"
	}
	roleCheck := role
	if args.action == "list" {
		roleCheck = ""
	}
	var channelKeys *keys.ChannelKeys
	if config.embeddedKeys != nil && args.keyFile == "" {
		channelKeys = config.embeddedKeys
		if channelKeys.Channel != args.channel || roleCheck != "" && channelKeys.Role != roleCheck {
			fmt.Fprintln(os.Stderr, "error: embedded key bundle does not match the requested channel or role")
			return 1
		}
	} else {
		if args.keyFile == "" {
			args.keyFile = filepath.Join(args.stateDir, "keys", args.channel, role+".json")
		}
		channelKeys, err = keys.Load(args.keyFile, args.channel, roleCheck)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	apiKey, err := apiCredential(config.embeddedAPIKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	mailbox := transport.New(apiKey)
	if args.action == "list" {
		if err := remoteListing(mailbox, channelKeys, args.channel, args.json); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}
	database, err := state.Open(path, receiver, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer database.Close()
	logger := func(message string) {
		if !args.quiet {
			fmt.Fprintln(os.Stderr, message)
		}
	}
	instance, err := service.New(mailbox, database, channelKeys, service.Options{Channel: args.channel, Node: args.node, Peer: args.peer, Receiver: receiver, OutDir: args.out, TTL: args.ttl, MaxOutput: args.maxOutput, MaxTransfer: args.maxTransfer, ExecTimeout: time.Duration(args.execTimeout) * time.Second, Batch: args.batch, Log: logger})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer instance.Close()
	signals := make(chan os.Signal, 1)
	if receiver {
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
	}
	code, err := run(instance, args, signals)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if code == 130 {
		fmt.Fprintln(os.Stderr, "\nInterrupted; job and delivery state is saved.")
	}
	return code
}
