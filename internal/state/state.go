// Package state is the per-user pin of a log key and checkpoint history.
package state

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ao3575911/atomhandle/internal/checkpoint"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

// ErrNoKey means this origin has no trusted log key yet.
var ErrNoKey = errors.New("no trusted log key")

// ErrLogKey is returned when a new key does not match the pinned one.
var ErrLogKey = errors.New("log key does not match pinned key")

// Record is one checkpoint the client has accepted, plus the consistency
// proof linking it to the previous record (empty for the first).
type Record struct {
	Size      uint64
	Root      []byte
	Note      string
	ProofFrom uint64
	Proof     [][]byte
}

type recordJSON struct {
	Size      uint64   `json:"size"`
	Root      string   `json:"root"`
	Note      string   `json:"checkpoint"`
	ProofFrom uint64   `json:"proof_from"`
	Proof     []string `json:"proof"`
}

// Store is ~/.atom (or ATOM_HOME).
type Store struct {
	home string
}

// Open ensures the home directory exists.
func Open(home string) (*Store, error) {
	if home == "" {
		return nil, errors.New("empty home")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return nil, err
	}
	return &Store{home: home}, nil
}

// LogKey returns the pinned verifier key for origin.
func (s *Store) LogKey(origin string) (string, error) {
	b, err := os.ReadFile(s.keyPath(origin))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: %s", ErrNoKey, origin)
	}
	if err != nil {
		return "", err
	}
	k := string(bytes.TrimSpace(b))
	if k == "" {
		return "", fmt.Errorf("%w: %s", ErrNoKey, origin)
	}
	return k, nil
}

// PinLogKey records vkey for origin. A different existing key is rejected.
func (s *Store) PinLogKey(origin, vkey string) error {
	if origin == "" || vkey == "" {
		return fmt.Errorf("empty origin or log key")
	}
	cur, err := s.LogKey(origin)
	if err == nil {
		if cur != vkey {
			return fmt.Errorf("%w for %s", ErrLogKey, origin)
		}
		return nil
	}
	if !errors.Is(err, ErrNoKey) {
		return err
	}
	dir := s.originDir(origin)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "origin"), []byte(origin+"\n"), 0o644); err != nil {
		return err
	}
	return writeNew(s.keyPath(origin), []byte(vkey+"\n"), 0o644)
}

// History returns accepted checkpoints for origin, verified with trustedKey.
// A missing history file is an empty slice.
func (s *Store) History(origin, trustedKey string) ([]Record, error) {
	f, err := os.Open(s.histPath(origin))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var out []Record
	for sc.Scan() {
		var rj recordJSON
		if err := json.Unmarshal(sc.Bytes(), &rj); err != nil {
			return nil, fmt.Errorf("checkpoint history: %w", err)
		}
		cp, err := checkpoint.Parse(rj.Note, trustedKey)
		if err != nil {
			return nil, fmt.Errorf("checkpoint history: %w", err)
		}
		if cp.Origin != origin || cp.Size != rj.Size || codec.Encode(cp.Root) != rj.Root {
			return nil, fmt.Errorf("checkpoint history: record does not match note at size %d", rj.Size)
		}
		proof, err := decodeProof(rj.Proof)
		if err != nil {
			return nil, err
		}
		out = append(out, Record{
			Size:      cp.Size,
			Root:      cp.Root,
			Note:      rj.Note,
			ProofFrom: rj.ProofFrom,
			Proof:     proof,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AppendCheckpoint adds a checkpoint that is already linked to the current
// history. The caller must have verified proof cryptographically.
func (s *Store) AppendCheckpoint(origin, trustedKey string, cp *checkpoint.Checkpoint, proofFrom uint64, proof [][]byte) error {
	if cp.Origin != origin {
		return fmt.Errorf("origin mismatch")
	}
	if _, err := checkpoint.Parse(cp.Note, trustedKey); err != nil {
		return err
	}
	hist, err := s.History(origin, trustedKey)
	if err != nil {
		return err
	}
	if len(hist) == 0 {
		if proofFrom != 0 || len(proof) != 0 {
			return fmt.Errorf("first checkpoint must not carry a proof")
		}
	} else {
		last := hist[len(hist)-1]
		if cp.Size <= last.Size {
			return fmt.Errorf("checkpoint size %d is not after %d", cp.Size, last.Size)
		}
		if proofFrom != last.Size {
			return fmt.Errorf("proof must start at %d", last.Size)
		}
	}
	if proof == nil {
		proof = [][]byte{}
	}
	rj := recordJSON{
		Size:      cp.Size,
		Root:      codec.Encode(cp.Root),
		Note:      cp.Note,
		ProofFrom: proofFrom,
		Proof:     merkle.EncodeHashes(proof),
	}
	line, err := json.Marshal(rj)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	dir := s.originDir(origin)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.histPath(origin), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

// Check reports whether cp is consistent with hist.
// If a newer pinned checkpoint is linked by the stored proofs, latest is that
// size. If nothing newer is pinned, latest equals cp.Size.
func Check(cp *checkpoint.Checkpoint, hist []Record) (latest uint64, err error) {
	if len(hist) == 0 {
		return cp.Size, nil
	}
	anchor := -1
	for i, h := range hist {
		if h.Size != cp.Size {
			continue
		}
		if !bytes.Equal(h.Root, cp.Root) {
			return 0, fmt.Errorf("log equivocation at size %d", cp.Size)
		}
		anchor = i
	}
	latestRec := hist[len(hist)-1]
	if anchor < 0 {
		if latestRec.Size > cp.Size {
			return 0, fmt.Errorf("pinned checkpoint size %d is newer than passport size %d but no consistency proof links them", latestRec.Size, cp.Size)
		}
		return cp.Size, nil
	}
	for i := anchor; i < len(hist)-1; i++ {
		a := hist[i]
		b := hist[i+1]
		if b.ProofFrom != a.Size || b.Size <= a.Size {
			return 0, fmt.Errorf("checkpoint history break at size %d", b.Size)
		}
		if err := merkle.VerifyConsistency(a.Size, b.Size, a.Root, b.Root, b.Proof); err != nil {
			return 0, fmt.Errorf("consistency %d -> %d: %w", a.Size, b.Size, err)
		}
	}
	return latestRec.Size, nil
}

func (s *Store) originDir(origin string) string {
	sum := sha256.Sum256([]byte(origin))
	return filepath.Join(s.home, "logs", hex.EncodeToString(sum[:]))
}

func (s *Store) keyPath(origin string) string {
	return filepath.Join(s.originDir(origin), "log.vkey")
}

func (s *Store) histPath(origin string) string {
	return filepath.Join(s.originDir(origin), "checkpoints.jsonl")
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("file exists: %s", path)
	}
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

func decodeProof(ss []string) ([][]byte, error) {
	if ss == nil {
		return [][]byte{}, nil
	}
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := codec.DecodeFixed(s, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("checkpoint history proof: %w", err)
		}
		out[i] = b
	}
	return out, nil
}
