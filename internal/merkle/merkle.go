// Package merkle implements the RFC 6962 / RFC 9162 Merkle tree
// (SHA-256, leaf prefix 0x00, node prefix 0x01).
package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"

	"github.com/ao3575911/atomhandle/internal/codec"
)

const maxProofHashes = 64

// ErrProof is returned for a bad inclusion or consistency proof.
var ErrProof = errors.New("invalid proof")

// ErrRange is returned when an index or tree size is out of range.
var ErrRange = errors.New("index or size out of range")

// EmptyRoot is MTH({}) = SHA-256().
func EmptyRoot() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

// LeafHash is MTH of a one-element list: SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Tree is an append-only list of leaf hashes.
type Tree struct {
	leaves [][]byte
}

// New returns an empty tree.
func New() *Tree {
	return &Tree{}
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 {
	return uint64(len(t.leaves))
}

// Append adds raw leaf data and returns its leaf hash.
func (t *Tree) Append(data []byte) []byte {
	h := LeafHash(data)
	t.leaves = append(t.leaves, h)
	return clone(h)
}

// Root is the Merkle tree hash of every leaf, or EmptyRoot when empty.
func (t *Tree) Root() []byte {
	r, _ := t.RootAt(t.Size())
	return r
}

// RootAt is the Merkle tree hash of the first size leaves.
func (t *Tree) RootAt(size uint64) ([]byte, error) {
	if size > t.Size() {
		return nil, fmt.Errorf("%w: size %d > %d", ErrRange, size, t.Size())
	}
	if size == 0 {
		return EmptyRoot(), nil
	}
	return clone(t.calc().mth(0, int(size))), nil
}

// InclusionProof returns PATH(index, leaves[:size]) per RFC 9162 §2.1.3.1.
func (t *Tree) InclusionProof(index, size uint64) ([][]byte, error) {
	if size == 0 || size > t.Size() || index >= size {
		return nil, fmt.Errorf("%w: index %d size %d tree %d", ErrRange, index, size, t.Size())
	}
	p := t.calc().path(0, int(size), int(index))
	if p == nil {
		p = [][]byte{}
	}
	return p, nil
}

// ConsistencyProof returns PROOF(first, leaves[:second]) per RFC 9162 §2.1.4.1.
// first == second yields an empty proof. first must be non-zero (a proof from
// the empty tree is undefined).
func (t *Tree) ConsistencyProof(first, second uint64) ([][]byte, error) {
	if first == 0 || second == 0 || first > second || second > t.Size() {
		return nil, fmt.Errorf("%w: consistency %d -> %d (tree %d)", ErrRange, first, second, t.Size())
	}
	if first == second {
		return [][]byte{}, nil
	}
	p := t.calc().subproof(0, int(second), int(first), true)
	if p == nil {
		p = [][]byte{}
	}
	return p, nil
}

// VerifyInclusion checks that leafHash at index is in a tree of the given
// size with the given root. leafHash must already be a leaf hash.
// Algorithm: RFC 9162 §2.1.3.2.
func VerifyInclusion(leafHash []byte, index, size uint64, proof [][]byte, root []byte) error {
	if len(leafHash) != sha256.Size || len(root) != sha256.Size {
		return fmt.Errorf("%w: hash length", ErrProof)
	}
	if index >= size {
		return fmt.Errorf("%w: index %d >= size %d", ErrProof, index, size)
	}
	if len(proof) > maxProofHashes {
		return fmt.Errorf("%w: too long", ErrProof)
	}
	for _, p := range proof {
		if len(p) != sha256.Size {
			return fmt.Errorf("%w: element length", ErrProof)
		}
	}
	fn := index
	sn := size - 1
	r := clone(leafHash)
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytesEqual(r, root) {
		return fmt.Errorf("%w: inclusion root mismatch", ErrProof)
	}
	return nil
}

// VerifyConsistency checks a consistency proof between two tree heads.
// Algorithm: RFC 9162 §2.1.4.2. first == second requires an empty proof and
// equal roots. first must be non-zero.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) error {
	if len(firstRoot) != sha256.Size || len(secondRoot) != sha256.Size {
		return fmt.Errorf("%w: hash length", ErrProof)
	}
	if first == 0 || second == 0 || first > second {
		return fmt.Errorf("%w: sizes %d -> %d", ErrProof, first, second)
	}
	if len(proof) > maxProofHashes {
		return fmt.Errorf("%w: too long", ErrProof)
	}
	for _, p := range proof {
		if len(p) != sha256.Size {
			return fmt.Errorf("%w: element length", ErrProof)
		}
	}
	if first == second {
		if len(proof) != 0 {
			return fmt.Errorf("%w: non-empty proof for equal sizes", ErrProof)
		}
		if !bytesEqual(firstRoot, secondRoot) {
			return fmt.Errorf("%w: root mismatch", ErrProof)
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("%w: empty consistency proof", ErrProof)
	}
	path := proof
	// When the first tree is a perfect subtree its hash is not in the proof.
	if first&(first-1) == 0 {
		path = make([][]byte, 0, len(proof)+1)
		path = append(path, firstRoot)
		path = append(path, proof...)
	}
	fn := first - 1
	sn := second - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr := clone(path[0])
	sr := clone(path[0])
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytesEqual(fr, firstRoot) || !bytesEqual(sr, secondRoot) {
		return fmt.Errorf("%w: consistency root mismatch", ErrProof)
	}
	return nil
}

// Inclusion is a decoded inclusion-proof message.
type Inclusion struct {
	Index    uint64
	Size     uint64
	LeafHash []byte
	Hashes   [][]byte
}

// Consistency is a decoded consistency-proof message.
type Consistency struct {
	First  uint64
	Second uint64
	Hashes [][]byte
}

type inclusionWire struct {
	Index    uint64   `json:"index"`
	Size     uint64   `json:"size"`
	LeafHash string   `json:"leaf_hash"`
	Hashes   []string `json:"hashes"`
}

type consistencyWire struct {
	First  uint64   `json:"first"`
	Second uint64   `json:"second"`
	Hashes []string `json:"hashes"`
}

// ParseInclusionProof parses an inclusion proof JSON object.
func ParseInclusionProof(data []byte) (*Inclusion, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, fmt.Errorf("%w: size", ErrProof)
	}
	dec := json.NewDecoder(bytesNew(data))
	dec.DisallowUnknownFields()
	var w inclusionWire
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProof, err)
	}
	if err := rejectTrailing(dec); err != nil {
		return nil, err
	}
	if w.Hashes == nil {
		return nil, fmt.Errorf("%w: missing hashes", ErrProof)
	}
	leaf, err := codec.DecodeFixed(w.LeafHash, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf_hash: %v", ErrProof, err)
	}
	hashes, err := decodeHashes(w.Hashes)
	if err != nil {
		return nil, err
	}
	return &Inclusion{Index: w.Index, Size: w.Size, LeafHash: leaf, Hashes: hashes}, nil
}

// ParseConsistencyProof parses a consistency proof JSON object.
func ParseConsistencyProof(data []byte) (*Consistency, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, fmt.Errorf("%w: size", ErrProof)
	}
	dec := json.NewDecoder(bytesNew(data))
	dec.DisallowUnknownFields()
	var w consistencyWire
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProof, err)
	}
	if err := rejectTrailing(dec); err != nil {
		return nil, err
	}
	if w.Hashes == nil {
		return nil, fmt.Errorf("%w: missing hashes", ErrProof)
	}
	hashes, err := decodeHashes(w.Hashes)
	if err != nil {
		return nil, err
	}
	return &Consistency{First: w.First, Second: w.Second, Hashes: hashes}, nil
}

// EncodeHashes encodes proof hashes as standard base64.
func EncodeHashes(hs [][]byte) []string {
	if hs == nil {
		return []string{}
	}
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = codec.Encode(h)
	}
	return out
}

func decodeHashes(ss []string) ([][]byte, error) {
	if len(ss) > maxProofHashes {
		return nil, fmt.Errorf("%w: too many hashes", ErrProof)
	}
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := codec.DecodeFixed(s, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("%w: hash %d: %v", ErrProof, i, err)
		}
		out[i] = b
	}
	return out, nil
}

type treeCalc struct {
	leaves [][]byte
	memo   map[[2]int][]byte
}

func (t *Tree) calc() *treeCalc {
	return &treeCalc{leaves: t.leaves, memo: make(map[[2]int][]byte)}
}

func (c *treeCalc) mth(lo, hi int) []byte {
	if hi == lo+1 {
		return c.leaves[lo]
	}
	key := [2]int{lo, hi}
	if v, ok := c.memo[key]; ok {
		return v
	}
	k := largestPow2LessThan(hi - lo)
	v := NodeHash(c.mth(lo, lo+k), c.mth(lo+k, hi))
	c.memo[key] = v
	return v
}

// path is PATH for absolute leaf index m inside [lo, hi).
func (c *treeCalc) path(lo, hi, m int) [][]byte {
	n := hi - lo
	if n == 1 {
		return [][]byte{}
	}
	k := largestPow2LessThan(n)
	if m < lo+k {
		return append(c.path(lo, lo+k, m), clone(c.mth(lo+k, hi)))
	}
	return append(c.path(lo+k, hi, m), clone(c.mth(lo, lo+k)))
}

// subproof is SUBPROOF for the first mRel leaves of [lo, hi).
func (c *treeCalc) subproof(lo, hi, mRel int, known bool) [][]byte {
	n := hi - lo
	if mRel == n {
		if known {
			return [][]byte{}
		}
		return [][]byte{clone(c.mth(lo, hi))}
	}
	k := largestPow2LessThan(n)
	if mRel <= k {
		return append(c.subproof(lo, lo+k, mRel, known), clone(c.mth(lo+k, hi)))
	}
	return append(c.subproof(lo+k, hi, mRel-k, false), clone(c.mth(lo, lo+k)))
}

// largestPow2LessThan returns the largest power of two strictly less than n.
// n must be >= 2.
func largestPow2LessThan(n int) int {
	// floorPow2(n-1) == 1 << (bits.Len(n-1)-1)
	return 1 << (bits.Len(uint(n-1)) - 1)
}

func bytesNew(data []byte) *bytes.Reader { return bytes.NewReader(data) }

func rejectTrailing(dec *json.Decoder) error {
	if dec.More() {
		return fmt.Errorf("%w: trailing data", ErrProof)
	}
	return nil
}

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
