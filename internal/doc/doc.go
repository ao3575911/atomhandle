// Package doc builds and verifies signed did:atom handle documents.
package doc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/handle"
)

const (
	// DocumentPrefix is the domain separator for owner signatures.
	DocumentPrefix = "atomhandle-document-v1\n"
	// ArtifactPrefix is the domain separator for agent artifact signatures.
	ArtifactPrefix = "atomhandle-artifact-v1\n"

	maxDocument = 64 << 10
	maxAgents   = 16
	// CreatedSkew is how far a created timestamp may sit in the future.
	CreatedSkew = 5 * time.Minute
)

// ErrDocument is returned for a malformed or incorrectly signed document.
var ErrDocument = errors.New("invalid document")

// Body is the unsigned handle document.
type Body struct {
	Handle  handle.Handle
	Owner   ed25519.PublicKey
	Agents  []ed25519.PublicKey
	Scopes  []string
	Created time.Time
	Expiry  time.Time
}

// Document is a signed handle document. Raw is the exact canonical JSON,
// including the signature, that is committed to the log.
type Document struct {
	Body
	Signature []byte
	Raw       []byte
}

type unsignedJSON struct {
	Handle  string   `json:"handle"`
	DID     string   `json:"did"`
	Owner   string   `json:"owner"`
	Agents  []string `json:"agents"`
	Scopes  []string `json:"scopes"`
	Created string   `json:"created"`
	Expiry  string   `json:"expiry"`
}

// NormalizeScopes checks scope tokens and returns them sorted and unique.
func NormalizeScopes(in []string) ([]string, error) {
	if in == nil {
		in = []string{}
	}
	out := append([]string(nil), in...)
	for _, s := range out {
		if err := checkScope(s); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, fmt.Errorf("%w: duplicate scope %q", ErrDocument, out[i])
		}
	}
	return out, nil
}

func checkScope(s string) error {
	if len(s) < 1 || len(s) > 63 {
		return fmt.Errorf("%w: scope length", ErrDocument)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-'
		if !ok || (i == 0 && (c < 'a' || c > 'z') && (c < '0' || c > '9')) {
			return fmt.Errorf("%w: scope %q", ErrDocument, s)
		}
	}
	return nil
}

// Sign signs body with the owner private key and returns canonical JSON.
func Sign(owner ed25519.PrivateKey, body Body) (*Document, error) {
	if len(owner) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: owner private key", ErrDocument)
	}
	pub := owner.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, body.Owner) {
		return nil, fmt.Errorf("%w: owner key mismatch", ErrDocument)
	}
	unsigned, err := canonicalUnsigned(body)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(owner, message(unsigned))
	raw, err := withSignature(unsigned, sig)
	if err != nil {
		return nil, err
	}
	doc, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// Parse parses and verifies a canonical signed document.
func Parse(raw []byte) (*Document, error) {
	if len(raw) == 0 || len(raw) > maxDocument {
		return nil, fmt.Errorf("%w: size", ErrDocument)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDocument, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrDocument)
	}
	if fields == nil {
		return nil, fmt.Errorf("%w: empty", ErrDocument)
	}
	allowed := []string{"handle", "did", "owner", "agents", "scopes", "created", "expiry", "signature"}
	if len(fields) != len(allowed) {
		return nil, fmt.Errorf("%w: fields", ErrDocument)
	}
	for _, k := range allowed {
		if _, ok := fields[k]; !ok {
			return nil, fmt.Errorf("%w: missing %s", ErrDocument, k)
		}
	}
	handleStr, err := decodeString(fields["handle"])
	if err != nil {
		return nil, fmt.Errorf("%w: handle: %v", ErrDocument, err)
	}
	didStr, err := decodeString(fields["did"])
	if err != nil {
		return nil, fmt.Errorf("%w: did: %v", ErrDocument, err)
	}
	ownerStr, err := decodeString(fields["owner"])
	if err != nil {
		return nil, fmt.Errorf("%w: owner: %v", ErrDocument, err)
	}
	agentStrs, err := decodeStringSlice(fields["agents"])
	if err != nil {
		return nil, fmt.Errorf("%w: agents: %v", ErrDocument, err)
	}
	scopeStrs, err := decodeStringSlice(fields["scopes"])
	if err != nil {
		return nil, fmt.Errorf("%w: scopes: %v", ErrDocument, err)
	}
	createdStr, err := decodeString(fields["created"])
	if err != nil {
		return nil, fmt.Errorf("%w: created: %v", ErrDocument, err)
	}
	expiryStr, err := decodeString(fields["expiry"])
	if err != nil {
		return nil, fmt.Errorf("%w: expiry: %v", ErrDocument, err)
	}
	sigStr, err := decodeString(fields["signature"])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrDocument, err)
	}

	h, err := handle.Parse(handleStr)
	if err != nil {
		return nil, err
	}
	if h.DID() != didStr {
		return nil, fmt.Errorf("%w: did does not match handle", ErrDocument)
	}
	owner, err := codec.DecodeFixed(ownerStr, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("%w: owner key: %v", ErrDocument, err)
	}
	if len(agentStrs) < 1 || len(agentStrs) > maxAgents {
		return nil, fmt.Errorf("%w: agent count", ErrDocument)
	}
	agents := make([]ed25519.PublicKey, len(agentStrs))
	seen := map[string]bool{}
	for i, s := range agentStrs {
		k, err := codec.DecodeFixed(s, ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("%w: agent key: %v", ErrDocument, err)
		}
		if seen[string(k)] {
			return nil, fmt.Errorf("%w: duplicate agent key", ErrDocument)
		}
		seen[string(k)] = true
		agents[i] = k
	}
	if err := scopesCanonical(scopeStrs); err != nil {
		return nil, err
	}
	created, err := parseTime(createdStr)
	if err != nil {
		return nil, fmt.Errorf("%w: created: %v", ErrDocument, err)
	}
	expiry, err := parseTime(expiryStr)
	if err != nil {
		return nil, fmt.Errorf("%w: expiry: %v", ErrDocument, err)
	}
	if !expiry.After(created) {
		return nil, fmt.Errorf("%w: expiry must be after created", ErrDocument)
	}
	sig, err := codec.DecodeFixed(sigStr, ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrDocument, err)
	}
	body := Body{
		Handle:  h,
		Owner:   owner,
		Agents:  agents,
		Scopes:  scopeStrs,
		Created: created,
		Expiry:  expiry,
	}
	unsigned, err := canonicalUnsigned(body)
	if err != nil {
		return nil, err
	}
	want, err := withSignature(unsigned, sig)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, raw) {
		return nil, fmt.Errorf("%w: not canonical", ErrDocument)
	}
	if !ed25519.Verify(owner, message(unsigned), sig) {
		return nil, fmt.Errorf("%w: owner signature", ErrDocument)
	}
	return &Document{Body: body, Signature: sig, Raw: append([]byte(nil), raw...)}, nil
}

// ValidAt reports whether now is inside [created-CreatedSkew, expiry).
func (d *Document) ValidAt(now time.Time) error {
	if now.Add(CreatedSkew).Before(d.Created) {
		return fmt.Errorf("%w: created time is in the future", ErrDocument)
	}
	if !now.Before(d.Expiry) {
		return fmt.Errorf("%w: expired at %s", ErrDocument, d.Expiry.Format(time.RFC3339))
	}
	return nil
}

// VerifyArtifact checks a detached signature over file made by an agent key
// listed on the document. The signature is over ArtifactMessage.
func (d *Document) VerifyArtifact(file, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: artifact signature length", ErrDocument)
	}
	msg := ArtifactMessage(d.Handle.String(), file)
	for _, k := range d.Agents {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("%w: artifact signature", ErrDocument)
}

// ArtifactMessage is the byte string an agent key signs for a file.
func ArtifactMessage(handleStr string, file []byte) []byte {
	sum := sha256.Sum256(file)
	var b bytes.Buffer
	b.WriteString(ArtifactPrefix)
	b.WriteString(handleStr)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	b.WriteByte('\n')
	return b.Bytes()
}

// SignArtifact returns a detached Ed25519 signature of file by agent.
func SignArtifact(agent ed25519.PrivateKey, handleStr string, file []byte) ([]byte, error) {
	if len(agent) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: agent private key", ErrDocument)
	}
	return ed25519.Sign(agent, ArtifactMessage(handleStr, file)), nil
}

func message(unsigned []byte) []byte {
	out := make([]byte, 0, len(DocumentPrefix)+len(unsigned))
	out = append(out, DocumentPrefix...)
	out = append(out, unsigned...)
	return out
}

func canonicalUnsigned(body Body) ([]byte, error) {
	if body.Handle.String() == "@/" || body.Handle.Owner == "" {
		return nil, fmt.Errorf("%w: handle", ErrDocument)
	}
	if _, err := handle.Parse(body.Handle.String()); err != nil {
		return nil, err
	}
	if len(body.Owner) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: owner key", ErrDocument)
	}
	if len(body.Agents) < 1 || len(body.Agents) > maxAgents {
		return nil, fmt.Errorf("%w: agent count", ErrDocument)
	}
	agents := make([]string, len(body.Agents))
	seen := map[string]bool{}
	for i, k := range body.Agents {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: agent key", ErrDocument)
		}
		if seen[string(k)] {
			return nil, fmt.Errorf("%w: duplicate agent key", ErrDocument)
		}
		seen[string(k)] = true
		agents[i] = codec.Encode(k)
	}
	if err := scopesCanonical(body.Scopes); err != nil {
		return nil, err
	}
	created := body.Created.UTC().Truncate(time.Second)
	expiry := body.Expiry.UTC().Truncate(time.Second)
	if !expiry.After(created) {
		return nil, fmt.Errorf("%w: expiry must be after created", ErrDocument)
	}
	u := unsignedJSON{
		Handle:  body.Handle.String(),
		DID:     body.Handle.DID(),
		Owner:   codec.Encode(body.Owner),
		Agents:  agents,
		Scopes:  body.Scopes,
		Created: created.Format(time.RFC3339),
		Expiry:  expiry.Format(time.RFC3339),
	}
	return marshalCanonical(u)
}

func scopesCanonical(scopes []string) error {
	if scopes == nil {
		return fmt.Errorf("%w: scopes", ErrDocument)
	}
	for i, s := range scopes {
		if err := checkScope(s); err != nil {
			return err
		}
		if i > 0 && scopes[i] <= scopes[i-1] {
			return fmt.Errorf("%w: scopes must be sorted and unique", ErrDocument)
		}
	}
	return nil
}

func withSignature(unsigned, sig []byte) ([]byte, error) {
	if len(unsigned) == 0 || unsigned[len(unsigned)-1] != '}' {
		return nil, fmt.Errorf("%w: canonical", ErrDocument)
	}
	sigJSON, err := marshalCanonical(codec.Encode(sig))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(unsigned)+len(sigJSON)+16)
	out = append(out, unsigned[:len(unsigned)-1]...)
	out = append(out, `,"signature":`...)
	out = append(out, sigJSON...)
	out = append(out, '}')
	return out, nil
}

func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("%w: encode", ErrDocument)
	}
	return b[:len(b)-1], nil
}

func decodeString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func decodeStringSlice(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errors.New("expected array")
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err != nil {
		return nil, err
	}
	if ss == nil {
		return nil, errors.New("null array")
	}
	return ss, nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	t = t.UTC().Truncate(time.Second)
	if t.Format(time.RFC3339) != s {
		return time.Time{}, errors.New("not canonical UTC RFC3339")
	}
	return t, nil
}
