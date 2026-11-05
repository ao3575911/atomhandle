// Package tlog is the append-only transparency log.
package tlog

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/ao3575911/atomhandle/internal/checkpoint"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/doc"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

// StatusError is a client error with an HTTP status.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

// Log is one origin's append-only Merkle tree, persisted as JSONL.
type Log struct {
	mu      sync.Mutex
	origin  string
	signer  note.Signer
	vkey    string
	dir     string
	file    *os.File
	tree    *merkle.Tree
	entries []entry
	handles map[string]uint64
}

type entry struct {
	handle string
	raw    []byte
	leaf   []byte
}

type entryLine struct {
	Index    uint64 `json:"index"`
	Handle   string `json:"handle"`
	Document string `json:"document"`
}

// Open loads a log from dir, generating an Ed25519 log key on first start.
// origin is the checkpoint origin and the note signer name; it is fixed for
// the life of the data directory.
func Open(dir, origin string) (*Log, error) {
	if dir == "" || origin == "" {
		return nil, errors.New("data dir and origin are required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	signer, vkey, err := loadOrCreateKey(dir, origin)
	if err != nil {
		return nil, err
	}
	if err := checkOrigin(dir, origin); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "entries.jsonl")
	if err := repairPartial(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	l := &Log{
		origin:  origin,
		signer:  signer,
		vkey:    vkey,
		dir:     dir,
		file:    f,
		tree:    merkle.New(),
		handles: map[string]uint64{},
	}
	if err := l.replay(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// Close releases the entries file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// LogKey is the note verifier key.
func (l *Log) LogKey() string { return l.vkey }

// Origin is the checkpoint origin.
func (l *Log) Origin() string { return l.origin }

// Size is the current tree size.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.Size()
}

// Submit verifies raw as a signed handle document and appends it.
func (l *Log) Submit(raw []byte, now time.Time) (index, size uint64, leaf []byte, proof [][]byte, cp *checkpoint.Checkpoint, err error) {
	d, err := doc.Parse(raw)
	if err != nil {
		return 0, 0, nil, nil, nil, &StatusError{Code: 400, Msg: err.Error()}
	}
	if err := d.ValidAt(now); err != nil {
		return 0, 0, nil, nil, nil, &StatusError{Code: 400, Msg: err.Error()}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.handles[d.Handle.String()]; ok {
		return 0, 0, nil, nil, nil, &StatusError{Code: 409, Msg: "handle already claimed"}
	}
	line, err := json.Marshal(entryLine{
		Index:    l.tree.Size(),
		Handle:   d.Handle.String(),
		Document: codec.Encode(d.Raw),
	})
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	line = append(line, '\n')
	off, err := l.file.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	if _, err := l.file.Write(line); err != nil {
		return 0, 0, nil, nil, nil, err
	}
	if err := l.file.Sync(); err != nil {
		_ = l.file.Truncate(off)
		_, _ = l.file.Seek(off, io.SeekStart)
		return 0, 0, nil, nil, nil, err
	}
	leaf = l.tree.Append(d.Raw)
	l.entries = append(l.entries, entry{handle: d.Handle.String(), raw: append([]byte(nil), d.Raw...), leaf: append([]byte(nil), leaf...)})
	l.handles[d.Handle.String()] = uint64(len(l.entries) - 1)
	index = uint64(len(l.entries) - 1)
	size = l.tree.Size()
	proof, err = l.tree.InclusionProof(index, size)
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	cp, err = l.signHeadLocked()
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	return index, size, leaf, proof, cp, nil
}

// Entry returns one stored document.
func (l *Log) Entry(index uint64) (raw, leaf []byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.entries)) {
		return nil, nil, &StatusError{Code: 404, Msg: "no such entry"}
	}
	e := l.entries[index]
	return append([]byte(nil), e.raw...), append([]byte(nil), e.leaf...), nil
}

// InclusionProof returns a proof for index in the tree of the given size.
func (l *Log) InclusionProof(index, size uint64) (leaf []byte, proof [][]byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.entries)) {
		return nil, nil, &StatusError{Code: 404, Msg: "no such entry"}
	}
	proof, err = l.tree.InclusionProof(index, size)
	if err != nil {
		return nil, nil, &StatusError{Code: 400, Msg: err.Error()}
	}
	return append([]byte(nil), l.entries[index].leaf...), proof, nil
}

// ConsistencyProof returns a proof between two tree sizes.
func (l *Log) ConsistencyProof(first, second uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := l.tree.ConsistencyProof(first, second)
	if err != nil {
		return nil, &StatusError{Code: 400, Msg: err.Error()}
	}
	return p, nil
}

// Head returns the current signed checkpoint.
func (l *Log) Head() (*checkpoint.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.signHeadLocked()
}

func (l *Log) signHeadLocked() (*checkpoint.Checkpoint, error) {
	size := l.tree.Size()
	root, err := l.tree.RootAt(size)
	if err != nil {
		return nil, err
	}
	text, err := checkpoint.Sign(l.signer, l.origin, size, root)
	if err != nil {
		return nil, err
	}
	return checkpoint.Parse(text, l.vkey)
}

func (l *Log) replay() error {
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(l.file)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var i uint64
	for sc.Scan() {
		var line entryLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return fmt.Errorf("entries.jsonl:%d: %w", i, err)
		}
		if line.Index != i {
			return fmt.Errorf("entries.jsonl:%d: index %d", i, line.Index)
		}
		raw, err := codec.Decode(line.Document)
		if err != nil {
			return fmt.Errorf("entries.jsonl:%d: %w", i, err)
		}
		d, err := doc.Parse(raw)
		if err != nil {
			return fmt.Errorf("entries.jsonl:%d: %w", i, err)
		}
		if d.Handle.String() != line.Handle {
			return fmt.Errorf("entries.jsonl:%d: handle mismatch", i)
		}
		if _, ok := l.handles[line.Handle]; ok {
			return fmt.Errorf("entries.jsonl:%d: duplicate handle %s", i, line.Handle)
		}
		leaf := l.tree.Append(d.Raw)
		l.entries = append(l.entries, entry{handle: line.Handle, raw: append([]byte(nil), d.Raw...), leaf: append([]byte(nil), leaf...)})
		l.handles[line.Handle] = i
		i++
	}
	return sc.Err()
}

func loadOrCreateKey(dir, origin string) (note.Signer, string, error) {
	skeyPath := filepath.Join(dir, "log.skey")
	vkeyPath := filepath.Join(dir, "log.vkey")
	_, serr := os.Stat(skeyPath)
	_, verr := os.Stat(vkeyPath)
	switch {
	case errors.Is(serr, os.ErrNotExist) && errors.Is(verr, os.ErrNotExist):
		skey, vkey, err := note.GenerateKey(rand.Reader, origin)
		if err != nil {
			return nil, "", err
		}
		if err := writeFile(skeyPath, []byte(skey+"\n"), 0o600); err != nil {
			return nil, "", err
		}
		if err := writeFile(vkeyPath, []byte(vkey+"\n"), 0o644); err != nil {
			return nil, "", err
		}
		signer, err := note.NewSigner(skey)
		if err != nil {
			return nil, "", err
		}
		return signer, vkey, nil
	case serr != nil:
		return nil, "", serr
	case verr != nil:
		return nil, "", verr
	}
	skey, err := readTrim(skeyPath)
	if err != nil {
		return nil, "", err
	}
	vkey, err := readTrim(vkeyPath)
	if err != nil {
		return nil, "", err
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, "", fmt.Errorf("log key: %w", err)
	}
	if _, err := note.NewVerifier(vkey); err != nil {
		return nil, "", fmt.Errorf("log key: %w", err)
	}
	if signer.Name() != origin {
		return nil, "", fmt.Errorf("log key name %q does not match origin %q", signer.Name(), origin)
	}
	return signer, vkey, nil
}

func checkOrigin(dir, origin string) error {
	path := filepath.Join(dir, "origin")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return writeFile(path, []byte(origin+"\n"), 0o644)
	}
	if err != nil {
		return err
	}
	got := string(bytes.TrimSpace(b))
	if got != origin {
		return fmt.Errorf("data dir origin is %q, not %q", got, origin)
	}
	return nil
}

func repairPartial(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || len(b) == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	if b[len(b)-1] == '\n' {
		return nil
	}
	cut := bytes.LastIndexByte(b, '\n')
	return os.WriteFile(path, b[:cut+1], 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	return os.Chmod(path, mode)
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
}
