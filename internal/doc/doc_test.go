package doc

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/handle"
)

func TestCanonicalGolden(t *testing.T) {
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, 32))
	agent := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x08}, 32))
	h, err := handle.Parse("@you/agent")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2027, 2, 3, 0, 0, 0, 0, time.UTC)
	doc, err := Sign(owner, Body{
		Handle:  h,
		Owner:   owner.Public().(ed25519.PublicKey),
		Agents:  []ed25519.PublicKey{agent.Public().(ed25519.PublicKey)},
		Scopes:  []string{"read", "write"},
		Created: created,
		Expiry:  expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	opub := codec.Encode(owner.Public().(ed25519.PublicKey))
	apub := codec.Encode(agent.Public().(ed25519.PublicKey))
	unsigned := `{"handle":"@you/agent","did":"did:atom:you/agent","owner":"` + opub + `","agents":["` + apub + `"],"scopes":["read","write"],"created":"2026-11-05T00:00:00Z","expiry":"2027-02-03T00:00:00Z"}`
	msg := append([]byte(DocumentPrefix), unsigned...)
	sig := ed25519.Sign(owner, msg)
	want := unsigned[:len(unsigned)-1] + `,"signature":"` + codec.Encode(sig) + `"}`
	if string(doc.Raw) != want {
		t.Fatalf("canonical\n got %s\nwant %s", doc.Raw, want)
	}
	again, err := Parse(doc.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if again.Handle.DID() != "did:atom:you/agent" {
		t.Fatal(again.Handle.DID())
	}
	raw := append([]byte(nil), doc.Raw...)
	raw[len(raw)-2] ^= 0x01
	if _, err := Parse(raw); err == nil {
		t.Fatal("accepted tampered document")
	}
	spaced := bytes.Replace(doc.Raw, []byte(`,"did"`), []byte(`, "did"`), 1)
	if _, err := Parse(spaced); err == nil {
		t.Fatal("accepted non-canonical spacing")
	}
}

func TestExpiryAndArtifact(t *testing.T) {
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	agent := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, 32))
	h, _ := handle.Parse("@you/agent")
	created := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	d, err := Sign(owner, Body{
		Handle:  h,
		Owner:   owner.Public().(ed25519.PublicKey),
		Agents:  []ed25519.PublicKey{agent.Public().(ed25519.PublicKey)},
		Scopes:  []string{},
		Created: created,
		Expiry:  created.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ValidAt(created.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.ValidAt(created.Add(time.Hour)); err == nil {
		t.Fatal("valid at expiry")
	}
	if err := d.ValidAt(created.Add(-2 * CreatedSkew)); err == nil {
		t.Fatal("valid long before created")
	}
	file := []byte("hello")
	sig, err := SignArtifact(agent, h.String(), file)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyArtifact(file, sig); err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyArtifact([]byte("hello!"), sig); err == nil {
		t.Fatal("accepted other file")
	}
	other, err := SignArtifact(agent, "@you/other", file)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyArtifact(file, other); err == nil {
		t.Fatal("accepted other handle")
	}
	if err := d.VerifyArtifact(file, ed25519.Sign(owner, ArtifactMessage(h.String(), file))); err == nil {
		t.Fatal("owner key is not an agent key")
	}
}

func TestRejectBadDocuments(t *testing.T) {
	cases := []string{
		``,
		`null`,
		`{}`,
		`[]`,
		`{"handle":"@you/agent"}`,
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Fatalf("accepted %s", c)
		}
	}
	scopes, err := NormalizeScopes([]string{"b", "a"})
	if err != nil || strings.Join(scopes, ",") != "a,b" {
		t.Fatalf("%v %v", scopes, err)
	}
	if _, err := NormalizeScopes([]string{"A"}); err == nil {
		t.Fatal("uppercase scope")
	}
	if _, err := NormalizeScopes([]string{"a", "a"}); err == nil {
		t.Fatal("duplicate")
	}
}

func FuzzParseDocument(f *testing.F) {
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x03}, 32))
	agent := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x04}, 32))
	h, err := handle.Parse("@you/agent")
	if err != nil {
		f.Fatal(err)
	}
	d, err := Sign(owner, Body{
		Handle:  h,
		Owner:   owner.Public().(ed25519.PublicKey),
		Agents:  []ed25519.PublicKey{agent.Public().(ed25519.PublicKey)},
		Scopes:  []string{"sign"},
		Created: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC),
		Expiry:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(d.Raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		parsed, err := Parse(data)
		if err != nil {
			return
		}
		if err := parsed.ValidAt(parsed.Created); err != nil && parsed.Expiry.After(parsed.Created) {
			// ValidAt may fail only on the future-created skew, never panic.
		}
		_ = parsed.VerifyArtifact([]byte("x"), bytes.Repeat([]byte{1}, 64))
	})
}
