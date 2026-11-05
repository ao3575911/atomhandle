// Package logclient is an HTTP client for atom-log.
package logclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/ao3575911/atomhandle/internal/api"
	"github.com/ao3575911/atomhandle/internal/codec"
)

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("log returned %d", e.Status)
	}
	return fmt.Sprintf("log returned %d: %s", e.Status, e.Message)
}

// Client talks to one log.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client for baseURL.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Submit posts a canonical handle document.
func (c *Client) Submit(doc []byte) (*api.SubmitResponse, error) {
	var out api.SubmitResponse
	if err := c.do(http.MethodPost, api.PathEntries, nil, doc, &out); err != nil {
		return nil, err
	}
	if out.Checkpoint == "" || out.LogKey == "" || out.InclusionProof == nil || out.TreeSize == 0 {
		return nil, fmt.Errorf("incomplete submit response")
	}
	return &out, nil
}

// Checkpoint fetches the current signed tree head.
func (c *Client) Checkpoint() (*api.CheckpointResponse, error) {
	var out api.CheckpointResponse
	if err := c.do(http.MethodGet, api.PathCheckpoint, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Consistency fetches a consistency proof between two sizes.
func (c *Client) Consistency(first, second uint64) ([][]byte, error) {
	q := url.Values{}
	q.Set("first", strconv.FormatUint(first, 10))
	q.Set("second", strconv.FormatUint(second, 10))
	var out api.ConsistencyResponse
	if err := c.do(http.MethodGet, api.PathConsistency, q, nil, &out); err != nil {
		return nil, err
	}
	if out.First != first || out.Second != second {
		return nil, fmt.Errorf("consistency response sizes")
	}
	if out.Hashes == nil {
		return nil, fmt.Errorf("consistency response missing hashes")
	}
	return decode(out.Hashes)
}

// Entry fetches one logged document.
func (c *Client) Entry(index uint64) (*api.EntryResponse, error) {
	var out api.EntryResponse
	path := api.PathEntries + "/" + strconv.FormatUint(index, 10)
	if err := c.do(http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Inclusion fetches an inclusion proof.
func (c *Client) Inclusion(index, size uint64) (*api.InclusionResponse, error) {
	q := url.Values{}
	q.Set("index", strconv.FormatUint(index, 10))
	q.Set("size", strconv.FormatUint(size, 10))
	var out api.InclusionResponse
	if err := c.do(http.MethodGet, api.PathInclusion, q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) do(method, path string, q url.Values, body []byte, out any) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("log url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er api.ErrorResponse
		_ = json.Unmarshal(buf, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(buf))
		}
		return &HTTPError{Status: resp.StatusCode, Message: er.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(buf, out); err != nil {
		return fmt.Errorf("log response: %w", err)
	}
	return nil
}

func decode(ss []string) ([][]byte, error) {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := codec.DecodeFixed(s, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("proof hash: %w", err)
		}
		out[i] = b
	}
	return out, nil
}
