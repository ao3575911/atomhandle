// Package checkpoint signs and verifies log checkpoints as signed notes
// (golang.org/x/mod/sumdb/note). The note text is three lines:
//
//	<origin>
//	<decimal size>
//	<standard-base64 SHA-256 root>
package checkpoint

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/ao3575911/atomhandle/internal/codec"
)

// ErrCheckpoint is returned for a malformed or badly signed checkpoint.
var ErrCheckpoint = errors.New("invalid checkpoint")

// Checkpoint is a verified signed tree head.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   []byte
	Note   string // exact signed note, including the signature block
	Key    string // verifier key that verified Note
}

// Sign returns the signed note for this tree head. signer.Name must equal origin.
func Sign(signer note.Signer, origin string, size uint64, root []byte) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: no signer", ErrCheckpoint)
	}
	if signer.Name() != origin {
		return "", fmt.Errorf("%w: signer name %q != origin %q", ErrCheckpoint, signer.Name(), origin)
	}
	body, err := formatBody(origin, size, root)
	if err != nil {
		return "", err
	}
	out, err := note.Sign(&note.Note{Text: body}, signer)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCheckpoint, err)
	}
	return string(out), nil
}

// Parse verifies a signed note with vkey and parses the checkpoint body.
// vkey is a note verifier key: "<name>+<8-hex-hash>+<base64-pubkey>".
func Parse(noteText, vkey string) (*Checkpoint, error) {
	if len(noteText) == 0 || len(noteText) > 1<<20 || len(vkey) == 0 || len(vkey) > 1<<16 {
		return nil, fmt.Errorf("%w: size", ErrCheckpoint)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("%w: log key: %v", ErrCheckpoint, err)
	}
	n, err := note.Open([]byte(noteText), note.VerifierList(v))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckpoint, err)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != v.Name() || n.Sigs[0].Hash != v.KeyHash() {
		return nil, fmt.Errorf("%w: signature set", ErrCheckpoint)
	}
	if len(n.UnverifiedSigs) != 0 {
		return nil, fmt.Errorf("%w: unverified signature", ErrCheckpoint)
	}
	origin, size, root, err := ParseBody(n.Text)
	if err != nil {
		return nil, err
	}
	if origin != v.Name() {
		return nil, fmt.Errorf("%w: origin %q != log key name %q", ErrCheckpoint, origin, v.Name())
	}
	return &Checkpoint{
		Origin: origin,
		Size:   size,
		Root:   root,
		Note:   noteText,
		Key:    vkey,
	}, nil
}

// ParseBody parses an unsigned checkpoint body (the note text, including its
// trailing newline, and not including the signature block).
func ParseBody(text string) (origin string, size uint64, root []byte, err error) {
	if len(text) == 0 || len(text) > 1<<20 || !strings.HasSuffix(text, "\n") {
		return "", 0, nil, fmt.Errorf("%w: body", ErrCheckpoint)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 || lines[0] == "" || lines[1] == "" || lines[2] == "" {
		return "", 0, nil, fmt.Errorf("%w: body lines", ErrCheckpoint)
	}
	origin = lines[0]
	if strings.ContainsAny(origin, " \t+") || strings.Contains(origin, "\n") {
		return "", 0, nil, fmt.Errorf("%w: origin", ErrCheckpoint)
	}
	size, err = strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return "", 0, nil, fmt.Errorf("%w: size", ErrCheckpoint)
	}
	root, err = codec.DecodeFixed(lines[2], sha256.Size)
	if err != nil {
		return "", 0, nil, fmt.Errorf("%w: root: %v", ErrCheckpoint, err)
	}
	return origin, size, root, nil
}

func formatBody(origin string, size uint64, root []byte) (string, error) {
	if origin == "" || strings.ContainsAny(origin, " \t+") {
		return "", fmt.Errorf("%w: origin", ErrCheckpoint)
	}
	if len(root) != sha256.Size {
		return "", fmt.Errorf("%w: root length", ErrCheckpoint)
	}
	if strconv.FormatUint(size, 10) == "" {
		return "", fmt.Errorf("%w: size", ErrCheckpoint)
	}
	return origin + "\n" + strconv.FormatUint(size, 10) + "\n" + codec.Encode(root) + "\n", nil
}
