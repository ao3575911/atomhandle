package tlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ao3575911/atomhandle/internal/api"
	"github.com/ao3575911/atomhandle/internal/checkpoint"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/doc"
	"github.com/ao3575911/atomhandle/internal/handle"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

func TestSubmitPersistAndProofs(t *testing.T) {
	dir := t.TempDir()
	const origin = "atom://test"
	lg, err := tlogOpen(dir, origin)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(lg.Handler(false))
	t.Cleanup(srv.Close)

	raw1 := mustDoc(t, "@ada/one", time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour))
	res1 := post(t, srv.URL, raw1, http.StatusOK)
	if res1.Index != 0 || res1.TreeSize != 1 {
		t.Fatalf("%+v", res1)
	}
	cp, err := checkpoint.Parse(res1.Checkpoint, res1.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 1 || cp.Origin != origin {
		t.Fatalf("%+v", cp)
	}
	leaf := merkle.LeafHash(raw1)
	proof, err := decode(res1.InclusionProof)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyInclusion(leaf, 0, 1, proof, cp.Root); err != nil {
		t.Fatal(err)
	}

	dup := postStatus(t, srv.URL, raw1)
	if dup != http.StatusConflict {
		t.Fatalf("duplicate status %d", dup)
	}
	bad := append([]byte(nil), raw1...)
	bad[20] ^= 0x01
	if postStatus(t, srv.URL, bad) != http.StatusBadRequest {
		t.Fatal("bad signature status")
	}
	expired := mustDoc(t, "@ada/old", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if postStatus(t, srv.URL, expired) != http.StatusBadRequest {
		t.Fatal("expired status")
	}

	raw2 := mustDoc(t, "@ada/two", time.Now().Add(-time.Minute), time.Now().Add(48*time.Hour))
	res2 := post(t, srv.URL, raw2, http.StatusOK)
	if res2.Index != 1 || res2.TreeSize != 2 {
		t.Fatalf("%+v", res2)
	}
	cp2, err := checkpoint.Parse(res2.Checkpoint, res2.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	cons := getJSON[api.ConsistencyResponse](t, srv.URL+"/v1/proof/consistency?first=1&second=2")
	ch, err := decode(cons.Hashes)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(1, 2, cp.Root, cp2.Root, ch); err != nil {
		t.Fatal(err)
	}

	entry := getJSON[api.EntryResponse](t, srv.URL+"/v1/entries/0")
	if !bytes.Equal(entry.Document, raw1) {
		t.Fatal("entry bytes")
	}
	incl := getJSON[api.InclusionResponse](t, srv.URL+"/v1/proof/inclusion?index=0&size=2")
	ih, err := decode(incl.Hashes)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyInclusion(merkle.LeafHash(raw1), 0, 2, ih, cp2.Root); err != nil {
		t.Fatal(err)
	}
	head := getJSON[api.CheckpointResponse](t, srv.URL+"/v1/checkpoint")
	if head.Size != 2 || head.LogKey != res1.LogKey || head.RootHash != codec.Encode(cp2.Root) {
		t.Fatalf("%+v", head)
	}

	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	lg2, err := tlogOpen(dir, origin)
	if err != nil {
		t.Fatal(err)
	}
	defer lg2.Close()
	if lg2.LogKey() != res1.LogKey || lg2.Size() != 2 {
		t.Fatalf("reopen key/size %s %d", lg2.LogKey(), lg2.Size())
	}
	if _, err := tlogOpen(dir, "atom://other"); err == nil {
		t.Fatal("reopened with a different origin")
	}
}

func TestConcurrentClaims(t *testing.T) {
	dir := t.TempDir()
	lg, err := tlogOpen(dir, "atom://conc")
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()
	srv := httptest.NewServer(lg.Handler(true))
	defer srv.Close()
	raws := make([][]byte, 8)
	for i := range raws {
		raws[i] = mustDoc(t, fmt.Sprintf("@n%d/agent", i), time.Now().Add(-time.Second), time.Now().Add(time.Hour))
	}
	var wg sync.WaitGroup
	errc := make(chan error, len(raws))
	for _, raw := range raws {
		wg.Add(1)
		go func(raw []byte) {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/v1/entries", "application/json", bytes.NewReader(raw))
			if err != nil {
				errc <- err
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				errc <- fmt.Errorf("status %d: %s", resp.StatusCode, b)
			}
		}(raw)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	if lg.Size() != 8 {
		t.Fatalf("size %d", lg.Size())
	}
}

func tlogOpen(dir, origin string) (*Log, error) { return Open(dir, origin) }

func mustDoc(t *testing.T, name string, created, expiry time.Time) []byte {
	t.Helper()
	h, err := handle.Parse(name)
	if err != nil {
		t.Fatal(err)
	}
	_, owner, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, agent, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := doc.Sign(owner, doc.Body{
		Handle:  h,
		Owner:   owner.Public().(ed25519.PublicKey),
		Agents:  []ed25519.PublicKey{agent.Public().(ed25519.PublicKey)},
		Scopes:  []string{},
		Created: created.UTC(),
		Expiry:  expiry.UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.Raw
}

func post(t *testing.T, base string, raw []byte, want int) api.SubmitResponse {
	t.Helper()
	resp, err := http.Post(base+"/v1/entries", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var out api.SubmitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func postStatus(t *testing.T, base string, raw []byte) int {
	t.Helper()
	resp, err := http.Post(base+"/v1/entries", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, resp.StatusCode, body)
	}
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func decode(ss []string) ([][]byte, error) {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := codec.DecodeFixed(s, 32)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}
