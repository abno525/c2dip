package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	"c2dip/internal/keys"
	"c2dip/internal/protocol"
	_ "modernc.org/sqlite"
)

type State struct {
	DB        *sql.DB
	lock      *os.File
	exclusive bool
}

type Job struct {
	ID, Direction, Peer, Kind, State, Detail string
	Created                                  int64
	Updated                                  float64
	Output                                   []byte
	Code                                     *int
	ResponseID, SavePath                     string
}

type Delivery struct {
	State string `json:"state"`
	Total int    `json:"total"`
	Sent  int    `json:"sent"`
}
type Part struct {
	ID      string
	Seq     int
	Name    string
	Expires int64
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inbox (id TEXT PRIMARY KEY, header TEXT NOT NULL, body BLOB,
 state TEXT NOT NULL DEFAULT 'collecting', expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS parts (id TEXT NOT NULL REFERENCES inbox(id) ON DELETE CASCADE,
 seq INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS garbage (remote_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, envelope TEXT NOT NULL, body BLOB NOT NULL,
 kind TEXT NOT NULL, peer TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', rounds INTEGER NOT NULL DEFAULT 0, sent_at REAL);
CREATE TABLE IF NOT EXISTS outparts (id TEXT NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
 seq INTEGER NOT NULL, name TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, direction TEXT NOT NULL, peer TEXT NOT NULL,
 kind TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued', created INTEGER NOT NULL, updated REAL NOT NULL,
 output BLOB NOT NULL DEFAULT X'', code INTEGER, detail TEXT NOT NULL DEFAULT '', response_id TEXT, save_path TEXT);
CREATE TABLE IF NOT EXISTS responses (request_id TEXT PRIMARY KEY,
 message_id TEXT NOT NULL REFERENCES inbox(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state, created);
CREATE INDEX IF NOT EXISTS inbox_state ON inbox(state);
PRAGMA user_version = 3;`

func Open(path string, exclusive, readOnly bool) (*State, error) {
	state := &State{exclusive: exclusive}
	if readOnly {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		dsn := "file:" + url.PathEscape(absolute) + "?mode=ro"
		state.DB, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		if err := state.DB.Ping(); err != nil {
			state.DB.Close()
			return nil, err
		}
		return state, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	state.lock = lock
	if exclusive {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return nil, fmt.Errorf("node state is already in use: %s", path)
		}
	}
	state.DB, err = sql.Open("sqlite", path)
	if err != nil {
		state.Close()
		return nil, err
	}
	state.DB.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL"} {
		if _, err := state.DB.Exec(pragma); err != nil {
			state.Close()
			return nil, err
		}
	}
	var version int
	if err := state.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		state.Close()
		return nil, err
	}
	if version != 0 && version != 3 {
		state.Close()
		return nil, fmt.Errorf("unsupported state database version: %d", version)
	}
	if _, err := state.DB.Exec(schema); err != nil {
		state.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		state.Close()
		return nil, err
	}
	return state, nil
}

func (s *State) Close() error {
	var result error
	if s.DB != nil {
		result = s.DB.Close()
		s.DB = nil
	}
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		if err := s.lock.Close(); result == nil {
			result = err
		}
		s.lock = nil
	}
	return result
}

func (s *State) Bind(role, channel, node, fingerprint string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{"role": role, "channel": channel, "node": node, "key_digest": fingerprint} {
		if _, err := tx.Exec("INSERT OR IGNORE INTO settings VALUES (?,?)", key, value); err != nil {
			return err
		}
		var stored string
		if err := tx.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&stored); err != nil {
			return err
		}
		if stored != value {
			return fmt.Errorf("state %s does not match this endpoint; use its original identity/key or a separate state directory", key)
		}
	}
	return tx.Commit()
}

func (s *State) AcquirePoll() (bool, func()) {
	if s.exclusive {
		return true, func() {}
	}
	if err := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false, func() {}
	}
	return true, func() { syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN) }
}

func envelope(message protocol.Message) string {
	raw, _ := json.Marshal(map[string]any{"id": message.ID, "channel": message.Channel, "sender": message.Sender,
		"recipient": message.Recipient, "kind": message.Kind, "created": message.Created, "expires": message.Expires})
	return string(raw)
}

func decodeMessage(encoded string, body []byte) (protocol.Message, error) {
	var fields struct {
		ID, Channel, Sender, Recipient, Kind string
		Created, Expires                     int64
	}
	if err := json.Unmarshal([]byte(encoded), &fields); err != nil {
		return protocol.Message{}, err
	}
	metadata, payload, err := protocol.UnpackBody(fields.Kind, body)
	if err != nil {
		return protocol.Message{}, err
	}
	return protocol.Message{ID: fields.ID, Channel: fields.Channel, Sender: fields.Sender, Recipient: fields.Recipient,
		Kind: fields.Kind, Created: fields.Created, Expires: fields.Expires, Metadata: metadata, Payload: payload}, nil
}

func headerJSON(header protocol.Header) string {
	raw, _ := json.Marshal(map[string]any{"id": header.ID, "channel": header.Channel, "sender": header.Sender,
		"recipient": header.Recipient, "kind": header.Kind, "created": header.Created, "expires": header.Expires,
		"total": header.Total, "digest": header.Digest})
	return string(raw)
}

func (s *State) Ingest(frame protocol.Frame, remoteID string, channelKeys *keys.ChannelKeys) (*protocol.Message, error) {
	header := frame.Header
	encoded := headerJSON(header)
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR IGNORE INTO garbage VALUES (?)", remoteID); err != nil {
		return nil, err
	}
	var storedHeader, state string
	var body []byte
	err = tx.QueryRow("SELECT header,state,body FROM inbox WHERE id=?", header.ID).Scan(&storedHeader, &state, &body)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = tx.Exec("INSERT INTO inbox(id,header,expires) VALUES (?,?,?)", header.ID, encoded, header.Expires); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if storedHeader != encoded {
		return nil, reject(tx, header.ID, errors.New("conflicting message header"))
	} else if state == "rejected" {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	} else if body != nil {
		message, err := decodeMessage(storedHeader, body)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &message, nil
	}
	var previous []byte
	err = tx.QueryRow("SELECT data FROM parts WHERE id=? AND seq=?", header.ID, frame.Index).Scan(&previous)
	if err == nil && string(previous) != string(frame.Data) {
		return nil, reject(tx, header.ID, errors.New("conflicting duplicate chunk"))
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO parts VALUES (?,?,?)", header.ID, frame.Index, frame.Data); err != nil {
		return nil, err
	}
	var size, count int
	if err := tx.QueryRow("SELECT COALESCE(SUM(LENGTH(data)),0),COUNT(*) FROM parts WHERE id=?", header.ID).Scan(&size, &count); err != nil {
		return nil, err
	}
	if size > protocol.MaxWireBody {
		return nil, reject(tx, header.ID, errors.New("message exceeds assembly limit"))
	}
	var message *protocol.Message
	if count == header.Total {
		rows, err := tx.Query("SELECT seq,data FROM parts WHERE id=? ORDER BY seq", header.ID)
		if err != nil {
			return nil, err
		}
		var frames []protocol.Frame
		for rows.Next() {
			var part protocol.Frame
			part.Header = header
			if err := rows.Scan(&part.Index, &part.Data); err != nil {
				rows.Close()
				return nil, err
			}
			frames = append(frames, part)
		}
		rows.Close()
		assembled, err := protocol.Assemble(frames, channelKeys)
		if err != nil {
			return nil, reject(tx, header.ID, err)
		}
		plaintext, err := assembled.Body()
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec("UPDATE inbox SET body=?,state='ready' WHERE id=?", plaintext, header.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("DELETE FROM parts WHERE id=?", header.ID); err != nil {
			return nil, err
		}
		message = &assembled
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return message, nil
}

func reject(tx *sql.Tx, id string, cause error) error {
	if _, err := tx.Exec("UPDATE inbox SET state='rejected' WHERE id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM parts WHERE id=?", id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return cause
}

func (s *State) message(query string, args ...any) (*protocol.Message, error) {
	var encoded string
	var body []byte
	err := s.DB.QueryRow(query, args...).Scan(&encoded, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	message, err := decodeMessage(encoded, body)
	return &message, err
}

func (s *State) Incoming(id string) (*protocol.Message, error) {
	return s.message("SELECT header,body FROM inbox WHERE id=? AND body IS NOT NULL", id)
}
func (s *State) OutMessage(id string) (*protocol.Message, error) {
	return s.message("SELECT envelope,body FROM outbox WHERE id=?", id)
}

func (s *State) Ready() ([]protocol.Message, error) {
	rows, err := s.DB.Query("SELECT header,body FROM inbox WHERE state='ready' ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []protocol.Message
	for rows.Next() {
		var encoded string
		var body []byte
		if err := rows.Scan(&encoded, &body); err != nil {
			return nil, err
		}
		message, err := decodeMessage(encoded, body)
		if err != nil {
			return nil, err
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (s *State) Handled(id string) error {
	_, err := s.DB.Exec("UPDATE inbox SET state='handled' WHERE id=?", id)
	return err
}
func (s *State) Discard(id string) error {
	_, err := s.DB.Exec("INSERT OR IGNORE INTO garbage VALUES (?)", id)
	return err
}
func (s *State) Deleted(id string) error {
	_, err := s.DB.Exec("DELETE FROM garbage WHERE remote_id=?", id)
	return err
}

func (s *State) Garbage() ([]string, error) {
	rows, err := s.DB.Query("SELECT remote_id FROM garbage LIMIT 64")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func enqueue(tx *sql.Tx, message protocol.Message, names []string) error {
	body, err := message.Body()
	if err != nil {
		return err
	}
	result, err := tx.Exec(`INSERT OR IGNORE INTO outbox
 (id,envelope,body,kind,peer,created,expires) VALUES (?,?,?,?,?,?,?)`, message.ID, envelope(message), body,
		message.Kind, message.Recipient, message.Created, message.Expires)
	if err != nil {
		return err
	}
	inserted, _ := result.RowsAffected()
	if inserted == 0 {
		return nil
	}
	for index, name := range names {
		if _, err := tx.Exec("INSERT INTO outparts(id,seq,name) VALUES (?,?,?)", message.ID, index, name); err != nil {
			return err
		}
	}
	return nil
}

func addJob(tx *sql.Tx, message protocol.Message, direction, peer string) error {
	_, err := tx.Exec(`INSERT OR IGNORE INTO jobs(id,direction,peer,kind,created,updated)
 VALUES (?,?,?,?,?,?)`, message.ID, direction, peer, message.Kind, message.Created, message.Created)
	return err
}

func (s *State) Enqueue(message protocol.Message, names []string, job bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := enqueue(tx, message, names); err != nil {
		return err
	}
	if job {
		if err := addJob(tx, message, "outbound", message.Recipient); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *State) EnsureAck(message protocol.Message, names []string, now float64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	var sentAt sql.NullFloat64
	rowErr := tx.QueryRow("SELECT state,sent_at FROM outbox WHERE id=?", message.ID).Scan(&state, &sentAt)
	if rowErr != nil && !errors.Is(rowErr, sql.ErrNoRows) {
		return rowErr
	}
	if err := enqueue(tx, message, names); err != nil {
		return err
	}
	if rowErr == nil && state == "delivered" && now-sentAt.Float64 >= 5 {
		if _, err := tx.Exec("UPDATE outbox SET state='pending' WHERE id=?", message.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE outparts SET sent=0 WHERE id=?", message.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *State) Acknowledge(reference, sender string) error {
	_, err := s.DB.Exec("UPDATE outbox SET state='delivered' WHERE id=? AND peer=? AND kind!='a'", reference, sender)
	return err
}

func (s *State) Prepare(now float64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []struct {
		query string
		args  []any
	}{
		{"UPDATE outbox SET state='expired' WHERE expires<=? AND state IN ('pending','waiting')", []any{now}},
		{"DELETE FROM parts WHERE id IN (SELECT id FROM inbox WHERE expires<=? AND state='collecting')", []any{now}},
		{"UPDATE inbox SET state='rejected' WHERE expires<=? AND state='collecting'", []any{now}},
	}
	for _, item := range statements {
		if _, err := tx.Exec(item.query, item.args...); err != nil {
			return err
		}
	}
	rows, err := tx.Query("SELECT id,rounds FROM outbox WHERE state='waiting' AND sent_at<=?", now-30)
	if err != nil {
		return err
	}
	type retry struct {
		id     string
		rounds int
	}
	var retries []retry
	for rows.Next() {
		var item retry
		if err := rows.Scan(&item.id, &item.rounds); err != nil {
			rows.Close()
			return err
		}
		retries = append(retries, item)
	}
	rows.Close()
	for _, item := range retries {
		next := "failed"
		if item.rounds < 3 {
			next = "pending"
		}
		if _, err := tx.Exec("UPDATE outbox SET state=? WHERE id=?", next, item.id); err != nil {
			return err
		}
		if next == "pending" {
			if _, err := tx.Exec("UPDATE outparts SET sent=0 WHERE id=?", item.id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *State) PendingParts(limit int) ([]Part, error) {
	rows, err := s.DB.Query(`SELECT p.id,p.seq,p.name,o.expires FROM outparts p JOIN outbox o ON o.id=p.id
 WHERE o.state='pending' AND p.sent=0 ORDER BY CASE o.kind WHEN 'a' THEN 0 WHEN 'k' THEN 1 WHEN 's' THEN 1
 WHEN 'r' THEN 2 ELSE 3 END,o.created,o.rowid,p.seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Part
	for rows.Next() {
		var part Part
		if err := rows.Scan(&part.ID, &part.Seq, &part.Name, &part.Expires); err != nil {
			return nil, err
		}
		result = append(result, part)
	}
	return result, rows.Err()
}

func (s *State) Sent(id string, sequence int, now float64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE outparts SET sent=1 WHERE id=? AND seq=?", id, sequence); err != nil {
		return err
	}
	var remaining int
	if err := tx.QueryRow("SELECT COUNT(*) FROM outparts WHERE id=? AND sent=0", id).Scan(&remaining); err != nil {
		return err
	}
	if remaining == 0 {
		if _, err := tx.Exec(`UPDATE outbox SET sent_at=?,rounds=rounds+1,state=CASE
 WHEN expires<=? THEN 'expired' WHEN kind='a' THEN 'delivered' ELSE 'waiting' END WHERE id=?`, now, now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *State) Retry(now float64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE outbox SET state='pending',rounds=0 WHERE state IN ('failed','waiting') AND expires>?", now); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE outparts SET sent=0 WHERE id IN (SELECT id FROM outbox WHERE state='pending')"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *State) Delivery(id string) (*Delivery, error) {
	var result Delivery
	err := s.DB.QueryRow(`SELECT o.state,COUNT(p.seq),COALESCE(SUM(p.sent),0) FROM outbox o
 LEFT JOIN outparts p ON p.id=o.id WHERE o.id=? GROUP BY o.id`, id).Scan(&result.State, &result.Total, &result.Sent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &result, err
}

func (s *State) count(query string) (int, error) {
	var count int
	err := s.DB.QueryRow(query).Scan(&count)
	return count, err
}
func (s *State) Pending() (int, error) {
	return s.count("SELECT COUNT(*) FROM outbox WHERE state IN ('pending','waiting')")
}
func (s *State) Unsent() (int, error) {
	return s.count("SELECT COUNT(*) FROM outbox WHERE state='pending'")
}
func (s *State) PendingIDs() ([]string, error) {
	rows, err := s.DB.Query("SELECT id FROM outbox WHERE state IN ('pending','waiting')")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanJob(scanner interface{ Scan(...any) error }) (*Job, error) {
	job := new(Job)
	var code sql.NullInt64
	var response, path sql.NullString
	err := scanner.Scan(&job.ID, &job.Direction, &job.Peer, &job.Kind, &job.State, &job.Created, &job.Updated,
		&job.Output, &code, &job.Detail, &response, &path)
	if err != nil {
		return nil, err
	}
	if code.Valid {
		value := int(code.Int64)
		job.Code = &value
	}
	job.ResponseID = response.String
	job.SavePath = path.String
	return job, nil
}

const jobColumns = "id,direction,peer,kind,state,created,updated,output,code,detail,response_id,save_path"

func (s *State) Job(id string) (*Job, error) {
	job, err := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return job, err
}

func (s *State) Jobs(direction string, states map[string]bool) ([]Job, error) {
	rows, err := s.DB.Query("SELECT " + jobColumns + " FROM jobs ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		if (direction == "" || job.Direction == direction) && (states == nil || states[job.State]) {
			jobs = append(jobs, *job)
		}
	}
	return jobs, rows.Err()
}

func (s *State) AcceptJob(message protocol.Message) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := addJob(tx, message, "inbound", message.Sender); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE inbox SET state='handled' WHERE id=?", message.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *State) Start(id string, now float64) (bool, error) {
	result, err := s.DB.Exec("UPDATE jobs SET state='running',updated=? WHERE id=? AND state='queued'", now, id)
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}
func (s *State) PlanPath(id, path string) error {
	_, err := s.DB.Exec("UPDATE jobs SET save_path=? WHERE id=?", path, id)
	return err
}
func (s *State) RecoverTransfer(id string) error {
	_, err := s.DB.Exec("UPDATE jobs SET state='queued' WHERE id=? AND state='running' AND kind IN ('f','g')", id)
	return err
}

func (s *State) Finish(id, jobState string, output []byte, code *int, detail string, now float64,
	reply *protocol.Message, names []string, path string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	responseID := any(nil)
	if reply != nil {
		if err := enqueue(tx, *reply, names); err != nil {
			return err
		}
		responseID = reply.ID
	}
	var codeValue any
	if code != nil {
		codeValue = *code
	}
	var pathValue any
	if path != "" {
		pathValue = path
	}
	if output == nil {
		output = []byte{}
	}
	_, err = tx.Exec(`UPDATE jobs SET state=?,output=?,code=?,detail=?,updated=?,response_id=COALESCE(?,response_id),
 save_path=COALESCE(?,save_path) WHERE id=?`, jobState, output, codeValue, detail, now, responseID, pathValue, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *State) Response(requestID string) (*protocol.Message, error) {
	return s.message(`SELECT i.header,i.body FROM responses r JOIN inbox i ON i.id=r.message_id WHERE r.request_id=?`, requestID)
}
func (s *State) SaveResponse(message protocol.Message, reference string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR IGNORE INTO responses VALUES (?,?)", reference, message.ID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE inbox SET state='handled' WHERE id=?", message.ID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE outbox SET state='delivered' WHERE id=? AND peer=?", reference, message.Sender); err != nil {
		return err
	}
	return tx.Commit()
}
