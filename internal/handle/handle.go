// Package handle parses @owner/name handles and did:atom identifiers.
package handle

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maxLabel = 63
	prefix   = "did:atom:"
)

// ErrHandle is returned when a handle or DID is not valid.
var ErrHandle = errors.New("invalid handle")

// Handle is a validated @owner/name name.
type Handle struct {
	Owner string
	Name  string
}

// String returns the handle, including the leading '@'.
func (h Handle) String() string {
	return "@" + h.Owner + "/" + h.Name
}

// DID returns did:atom:owner/name.
func (h Handle) DID() string {
	return prefix + h.Owner + "/" + h.Name
}

// Parse parses @owner/name. Owner and name are DNS-like labels:
// 1–63 characters, [a-z0-9], hyphens allowed only in the middle.
func Parse(s string) (Handle, error) {
	if len(s) < 3 || len(s) > 1+maxLabel+1+maxLabel || !strings.HasPrefix(s, "@") {
		return Handle{}, fmt.Errorf("%w: %q", ErrHandle, s)
	}
	rest := s[1:]
	owner, name, ok := strings.Cut(rest, "/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return Handle{}, fmt.Errorf("%w: %q", ErrHandle, s)
	}
	if err := checkLabel(owner); err != nil {
		return Handle{}, fmt.Errorf("%w: owner: %v", ErrHandle, err)
	}
	if err := checkLabel(name); err != nil {
		return Handle{}, fmt.Errorf("%w: name: %v", ErrHandle, err)
	}
	return Handle{Owner: owner, Name: name}, nil
}

// ParseDID parses did:atom:owner/name.
func ParseDID(s string) (Handle, error) {
	if !strings.HasPrefix(s, prefix) {
		return Handle{}, fmt.Errorf("%w: did %q", ErrHandle, s)
	}
	h, err := Parse("@" + strings.TrimPrefix(s, prefix))
	if err != nil {
		return Handle{}, fmt.Errorf("%w: did %q", ErrHandle, s)
	}
	if h.DID() != s {
		return Handle{}, fmt.Errorf("%w: did %q", ErrHandle, s)
	}
	return h, nil
}

func checkLabel(s string) error {
	if len(s) < 1 || len(s) > maxLabel {
		return fmt.Errorf("length %d", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return fmt.Errorf("bad character %q", c)
		}
	}
	return nil
}
