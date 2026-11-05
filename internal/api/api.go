// Package api is the atom-log HTTP wire format.
package api

import "encoding/json"

const (
	PathEntries     = "/v1/entries"
	PathInclusion   = "/v1/proof/inclusion"
	PathConsistency = "/v1/proof/consistency"
	PathCheckpoint  = "/v1/checkpoint"
)

// SubmitResponse is the body of a successful claim.
type SubmitResponse struct {
	Index          uint64   `json:"index"`
	TreeSize       uint64   `json:"tree_size"`
	LeafHash       string   `json:"leaf_hash"`
	InclusionProof []string `json:"inclusion_proof"`
	Checkpoint     string   `json:"checkpoint"`
	LogKey         string   `json:"log_key"`
}

// EntryResponse is one logged document.
type EntryResponse struct {
	Index    uint64          `json:"index"`
	Document json.RawMessage `json:"document"`
	LeafHash string          `json:"leaf_hash"`
}

// InclusionResponse is an inclusion proof for a leaf at a given tree size.
type InclusionResponse struct {
	Index    uint64   `json:"index"`
	Size     uint64   `json:"size"`
	LeafHash string   `json:"leaf_hash"`
	Hashes   []string `json:"hashes"`
}

// ConsistencyResponse is a consistency proof between two tree sizes.
type ConsistencyResponse struct {
	First  uint64   `json:"first"`
	Second uint64   `json:"second"`
	Hashes []string `json:"hashes"`
}

// CheckpointResponse is a signed tree head plus the log's verifier key.
type CheckpointResponse struct {
	Origin     string `json:"origin"`
	Size       uint64 `json:"size"`
	RootHash   string `json:"root_hash"`
	Checkpoint string `json:"checkpoint"`
	LogKey     string `json:"log_key"`
}

// ErrorResponse is a failed request.
type ErrorResponse struct {
	Error string `json:"error"`
}
