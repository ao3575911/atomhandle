package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"testing/quick"
)

func TestEmptyRoot(t *testing.T) {
	sum := sha256.Sum256(nil)
	if !bytes.Equal(EmptyRoot(), sum[:]) {
		t.Fatalf("empty root %x", EmptyRoot())
	}
	if !bytes.Equal(New().Root(), EmptyRoot()) {
		t.Fatal("empty tree")
	}
}

func TestLeafHashDomain(t *testing.T) {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte("hello"))
	if !bytes.Equal(LeafHash([]byte("hello")), h.Sum(nil)) {
		t.Fatal("leaf hash")
	}
	if bytes.Equal(LeafHash([]byte("hello")), LeafHash([]byte("world"))) {
		t.Fatal("collision")
	}
}

func TestRFC9162Shapes(t *testing.T) {
	// Figure in RFC 9162 §2.1.5: 7 leaves. Node names match the RFC.
	raw := make([][]byte, 7)
	for i := range raw {
		raw[i] = []byte{byte(i)}
	}
	tr := newRaw(raw)
	a := LeafHash(raw[0])
	b := LeafHash(raw[1])
	c := LeafHash(raw[2])
	d := LeafHash(raw[3])
	e := LeafHash(raw[4])
	f := LeafHash(raw[5])
	d6 := LeafHash(raw[6])
	g := NodeHash(a, b)
	h := NodeHash(c, d)
	i := NodeHash(e, f)
	j := d6
	k := NodeHash(g, h)
	l := NodeHash(i, j)
	root := NodeHash(k, l)
	if !bytes.Equal(tr.Root(), root) {
		t.Fatalf("root mismatch")
	}
	if !bytes.Equal(mustRoot(t, tr, 3), NodeHash(g, c)) && !bytes.Equal(mustRoot(t, tr, 3), NodeHash(NodeHash(a, b), c)) {
		t.Fatal("size 3")
	}
	// hash0 in the RFC is MTH of the first 3 leaves.
	hash0 := mustRoot(t, tr, 3)
	if !bytes.Equal(hash0, NodeHash(g, c)) {
		t.Fatalf("hash0")
	}
	if !bytes.Equal(mustRoot(t, tr, 4), k) {
		t.Fatal("hash1")
	}
	hash2 := NodeHash(k, i)
	if !bytes.Equal(mustRoot(t, tr, 6), hash2) {
		t.Fatal("hash2")
	}

	checkIncl := func(index int, want ...[]byte) {
		t.Helper()
		p, err := tr.InclusionProof(uint64(index), 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != len(want) {
			t.Fatalf("index %d proof len %d want %d", index, len(p), len(want))
		}
		for i := range want {
			if !bytes.Equal(p[i], want[i]) {
				t.Fatalf("index %d element %d", index, i)
			}
		}
		if err := VerifyInclusion(LeafHash(raw[index]), uint64(index), 7, p, root); err != nil {
			t.Fatal(err)
		}
	}
	checkIncl(0, b, h, l)
	checkIncl(3, c, g, l)
	checkIncl(4, f, j, k)
	checkIncl(6, i, k)

	checkCons := func(first int, want ...[]byte) {
		t.Helper()
		p, err := tr.ConsistencyProof(uint64(first), 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != len(want) {
			t.Fatalf("consistency %d len %d want %d", first, len(p), len(want))
		}
		for i := range want {
			if !bytes.Equal(p[i], want[i]) {
				t.Fatalf("consistency %d element %d", first, i)
			}
		}
		old := mustRoot(t, tr, uint64(first))
		if err := VerifyConsistency(uint64(first), 7, old, root, p); err != nil {
			t.Fatalf("verify consistency %d: %v", first, err)
		}
	}
	checkCons(3, c, d, g, l)
	checkCons(4, l)
	checkCons(6, i, j, k)
}

func TestSizesAgainstStack(t *testing.T) {
	for n := 0; n <= 32; n++ {
		raw := seq(n)
		tr := newRaw(raw)
		if !bytes.Equal(tr.Root(), stackRoot(raw)) {
			t.Fatalf("n=%d root", n)
		}
		for i := 0; i < n; i++ {
			p, err := tr.InclusionProof(uint64(i), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(LeafHash(raw[i]), uint64(i), uint64(n), p, tr.Root()); err != nil {
				t.Fatalf("n=%d i=%d inclusion: %v", n, i, err)
			}
			if n > 1 && i == 0 {
				bad := append([]byte(nil), tr.Root()...)
				bad[0] ^= 0xff
				if err := VerifyInclusion(LeafHash(raw[i]), uint64(i), uint64(n), p, bad); err == nil {
					t.Fatal("accepted bad root")
				}
			}
		}
		for m := 1; m <= n; m++ {
			p, err := tr.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			old := stackRoot(raw[:m])
			if err := VerifyConsistency(uint64(m), uint64(n), old, tr.Root(), p); err != nil {
				t.Fatalf("consistency %d->%d: %v", m, n, err)
			}
		}
	}
}

func TestHistoricalInclusion(t *testing.T) {
	raw := seq(6)
	tr := newRaw(raw)
	p, err := tr.InclusionProof(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	root4 := stackRoot(raw[:4])
	if err := VerifyInclusion(LeafHash(raw[1]), 1, 4, p, root4); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(LeafHash(raw[1]), 1, 4, p, tr.Root()); err == nil {
		t.Fatal("old proof verified against new root")
	}
}

func TestQuickInclusionAndConsistency(t *testing.T) {
	cfg := &quick.Config{MaxCount: 40}
	err := quick.Check(func(seed int64, n uint8) bool {
		size := int(n)%48 + 1
		return checkRandomTree(t, seed, size)
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func checkRandomTree(t *testing.T, seed int64, size int) bool {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	raw := make([][]byte, size)
	for i := range raw {
		buf := make([]byte, rng.Intn(20))
		rng.Read(buf)
		raw[i] = buf
	}
	tr := newRaw(raw)
	if !bytes.Equal(tr.Root(), stackRoot(raw)) {
		t.Errorf("seed %d size %d root", seed, size)
		return false
	}
	for i := range raw {
		p, err := tr.InclusionProof(uint64(i), uint64(size))
		if err != nil {
			t.Error(err)
			return false
		}
		if err := VerifyInclusion(LeafHash(raw[i]), uint64(i), uint64(size), p, tr.Root()); err != nil {
			t.Errorf("seed %d inclusion %d: %v", seed, i, err)
			return false
		}
		if len(p) > 0 {
			mut := clone(p[0])
			mut[0] ^= 0x01
			bad := append([][]byte{mut}, p[1:]...)
			if err := VerifyInclusion(LeafHash(raw[i]), uint64(i), uint64(size), bad, tr.Root()); err == nil {
				t.Errorf("seed %d mutated proof accepted", seed)
				return false
			}
		}
	}
	// Append-only: old proofs still match the old root, and consistency holds.
	if size >= 2 {
		cut := 1 + rng.Intn(size-1)
		oldTree := newRaw(raw[:cut])
		p, err := tr.ConsistencyProof(uint64(cut), uint64(size))
		if err != nil {
			t.Error(err)
			return false
		}
		if err := VerifyConsistency(uint64(cut), uint64(size), oldTree.Root(), tr.Root(), p); err != nil {
			t.Errorf("seed %d consistency %d->%d: %v", seed, cut, size, err)
			return false
		}
		for i := 0; i < cut; i++ {
			op, err := oldTree.InclusionProof(uint64(i), uint64(cut))
			if err != nil {
				t.Error(err)
				return false
			}
			if err := VerifyInclusion(LeafHash(raw[i]), uint64(i), uint64(cut), op, oldTree.Root()); err != nil {
				t.Error(err)
				return false
			}
		}
	}
	return true
}

func TestProofJSON(t *testing.T) {
	raw := seq(3)
	tr := newRaw(raw)
	p, err := tr.InclusionProof(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(inclusionWire{
		Index:    0,
		Size:     3,
		LeafHash: mustB64(LeafHash(raw[0])),
		Hashes:   EncodeHashes(p),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseInclusionProof(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Index != 0 || got.Size != 3 || !bytes.Equal(got.LeafHash, LeafHash(raw[0])) {
		t.Fatalf("parsed %+v", got)
	}
	cp, err := tr.ConsistencyProof(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(consistencyWire{First: 1, Second: 3, Hashes: EncodeHashes(cp)})
	if err != nil {
		t.Fatal(err)
	}
	cgot, err := ParseConsistencyProof(body)
	if err != nil {
		t.Fatal(err)
	}
	if cgot.First != 1 || cgot.Second != 3 || len(cgot.Hashes) != len(cp) {
		t.Fatalf("%+v", cgot)
	}
	if _, err := ParseInclusionProof([]byte(`{"index":0}`)); err == nil {
		t.Fatal("accepted incomplete proof")
	}
	if _, err := ParseConsistencyProof([]byte(`[]`)); err == nil {
		t.Fatal("accepted array")
	}
}

func TestRejectBadRanges(t *testing.T) {
	tr := newRaw(seq(2))
	if _, err := tr.InclusionProof(2, 2); err == nil {
		t.Fatal("index")
	}
	if _, err := tr.ConsistencyProof(0, 2); err == nil {
		t.Fatal("from empty")
	}
	if _, err := tr.ConsistencyProof(2, 1); err == nil {
		t.Fatal("backwards")
	}
	p, err := tr.ConsistencyProof(2, 2)
	if err != nil || len(p) != 0 {
		t.Fatalf("equal size proof %v %v", p, err)
	}
	if err := VerifyConsistency(2, 2, tr.Root(), tr.Root(), nil); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(LeafHash([]byte("nope")), 0, 0, nil, EmptyRoot()); err == nil {
		t.Fatal("size 0")
	}
}

func FuzzParseProof(f *testing.F) {
	raw := seq(2)
	tr := newRaw(raw)
	p, _ := tr.InclusionProof(0, 2)
	incl, _ := json.Marshal(inclusionWire{Index: 0, Size: 2, LeafHash: mustB64(LeafHash(raw[0])), Hashes: EncodeHashes(p)})
	cons, _ := json.Marshal(consistencyWire{First: 1, Second: 2, Hashes: EncodeHashes(mustProof(tr, 1, 2))})
	f.Add(incl)
	f.Add(cons)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"index":0,"size":1,"leaf_hash":"!!!!","hashes":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		if inc, err := ParseInclusionProof(data); err == nil {
			_ = VerifyInclusion(inc.LeafHash, inc.Index, inc.Size, inc.Hashes, inc.LeafHash)
		}
		if c, err := ParseConsistencyProof(data); err == nil {
			root := EmptyRoot()
			_ = VerifyConsistency(c.First, c.Second, root, root, c.Hashes)
		}
	})
}

func newRaw(raw [][]byte) *Tree {
	tr := New()
	for _, r := range raw {
		tr.Append(r)
	}
	return tr
}

func seq(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

func mustRoot(t *testing.T, tr *Tree, size uint64) []byte {
	t.Helper()
	r, err := tr.RootAt(size)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustProof(tr *Tree, first, second uint64) [][]byte {
	p, err := tr.ConsistencyProof(first, second)
	if err != nil {
		panic(err)
	}
	return p
}

func mustB64(b []byte) string {
	// local to avoid an import cycle in the assertion; tests may use codec via EncodeHashes
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		switch {
		case rem >= 3:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			out = append(out, table[n>>18], table[(n>>12)&63], table[(n>>6)&63], table[n&63])
		case rem == 2:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8
			out = append(out, table[n>>18], table[(n>>12)&63], table[(n>>6)&63], '=')
		default:
			n = uint32(b[i]) << 16
			out = append(out, table[n>>18], table[(n>>12)&63], '=', '=')
		}
	}
	return string(out)
}

// stackRoot is the RFC 9162 §2.1.2 algorithm, written separately from Tree
// so the tests are not comparing an implementation to itself.
func stackRoot(raw [][]byte) []byte {
	if len(raw) == 0 {
		return EmptyRoot()
	}
	var stack [][]byte
	merge := func() {
		right := stack[len(stack)-1]
		left := stack[len(stack)-2]
		stack = stack[:len(stack)-2]
		stack = append(stack, NodeHash(left, right))
	}
	for i, leaf := range raw {
		stack = append(stack, LeafHash(leaf))
		mc := 0
		for (i>>mc)&1 == 1 {
			mc++
		}
		for j := 0; j < mc; j++ {
			merge()
		}
	}
	for len(stack) > 1 {
		merge()
	}
	return stack[0]
}
