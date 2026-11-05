// Package codec is strict standard base64 for protocol fields.
package codec

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrEncoding is returned when a string is not canonical standard base64.
var ErrEncoding = errors.New("invalid base64")

var enc = base64.StdEncoding.Strict()

// Encode encodes b as canonical standard base64 (RFC 4648, with padding).
func Encode(b []byte) string {
	return enc.EncodeToString(b)
}

// Decode decodes canonical standard base64. Newlines and non-alphabet
// characters are rejected so each value has one encoding.
func Decode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
		if !ok {
			return nil, ErrEncoding
		}
	}
	out, err := enc.DecodeString(s)
	if err != nil {
		return nil, ErrEncoding
	}
	return out, nil
}

// DecodeFixed decodes standard base64 and requires exactly n bytes.
func DecodeFixed(s string, n int) ([]byte, error) {
	b, err := Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrEncoding, len(b), n)
	}
	return b, nil
}
