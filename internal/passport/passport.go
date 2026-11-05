// Package passport reads and verifies a self-contained claim bundle.
package passport

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ao3575911/atomhandle/internal/checkpoint"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/doc"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

// Bundle is the file written by atom claim.
type Bundle struct {
	Version        int             `json:"version"`
	Document       json.RawMessage `json:"document"`
	Index          uint64          `json:"index"`
	TreeSize       uint64          `json:"tree_size"`
	LeafHash       string          `json:"leaf_hash"`
	InclusionProof []string        `json:"inclusion_proof"`
	Checkpoint     string          `json:"checkpoint"`
	LogKey         string          `json:"log_key"`
}

// Result is a verified passport.
type Result struct {
	Document   *doc.Document
	Checkpoint *checkpoint.Checkpoint
	Index      uint64
	TreeSize   uint64
}

// Write writes b as JSON. The document field is the exact canonical bytes
// (MarshalIndent would reformat them and break the leaf hash).
func Write(path string, b *Bundle) error {
	raw, err := marshalBundle(b)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func marshalBundle(b *Bundle) ([]byte, error) {
	if len(b.Document) == 0 || b.Document[0] != '{' {
		return nil, fmt.Errorf("passport: document")
	}
	proof := b.InclusionProof
	if proof == nil {
		proof = []string{}
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	leaf, err := jsonString(b.LeafHash)
	if err != nil {
		return nil, err
	}
	cp, err := jsonString(b.Checkpoint)
	if err != nil {
		return nil, err
	}
	key, err := jsonString(b.LogKey)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "{\n  \"version\": %d,\n  \"document\": ", b.Version)
	buf.Write(b.Document)
	fmt.Fprintf(&buf, ",\n  \"index\": %d,\n  \"tree_size\": %d,\n  \"leaf_hash\": %s,\n  \"inclusion_proof\": %s,\n  \"checkpoint\": %s,\n  \"log_key\": %s\n}\n",
		b.Index, b.TreeSize, leaf, proofJSON, cp, key)
	return buf.Bytes(), nil
}

func jsonString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return out, nil
}

// Read parses a bundle without verifying it.
func Read(path string) (*Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse decodes a bundle. It does not verify signatures.
func Parse(raw []byte) (*Bundle, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, fmt.Errorf("passport: size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("passport: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("passport: trailing data")
	}
	return &b, nil
}

// Verify checks the document signature, expiry, inclusion proof, and the
// checkpoint signature against trustedLogKey. trustedLogKey must be the note
// verifier key of the log the caller trusts; the key inside the bundle is
// not trusted by itself and must match.
func Verify(b *Bundle, trustedLogKey string, now time.Time) (*Result, error) {
	if b == nil {
		return nil, fmt.Errorf("passport: nil")
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("passport: version %d", b.Version)
	}
	if trustedLogKey == "" {
		return nil, fmt.Errorf("passport: no trusted log key")
	}
	if b.LogKey != trustedLogKey {
		return nil, fmt.Errorf("passport: log key does not match trusted log key")
	}
	if len(b.Document) == 0 || b.InclusionProof == nil {
		return nil, fmt.Errorf("passport: missing fields")
	}
	d, err := doc.Parse(b.Document)
	if err != nil {
		return nil, err
	}
	if err := d.ValidAt(now); err != nil {
		return nil, err
	}
	cp, err := checkpoint.Parse(b.Checkpoint, trustedLogKey)
	if err != nil {
		return nil, err
	}
	if cp.Size != b.TreeSize {
		return nil, fmt.Errorf("passport: tree size %d != checkpoint size %d", b.TreeSize, cp.Size)
	}
	if b.Index >= b.TreeSize {
		return nil, fmt.Errorf("passport: index out of range")
	}
	leaf := merkle.LeafHash(d.Raw)
	if codec.Encode(leaf) != b.LeafHash {
		return nil, fmt.Errorf("passport: leaf hash mismatch")
	}
	proof := make([][]byte, len(b.InclusionProof))
	for i, s := range b.InclusionProof {
		h, err := codec.DecodeFixed(s, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("passport: inclusion proof: %w", err)
		}
		proof[i] = h
	}
	if err := merkle.VerifyInclusion(leaf, b.Index, b.TreeSize, proof, cp.Root); err != nil {
		return nil, fmt.Errorf("passport: %w", err)
	}
	return &Result{Document: d, Checkpoint: cp, Index: b.Index, TreeSize: b.TreeSize}, nil
}
