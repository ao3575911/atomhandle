package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

func TestSignAndParse(t *testing.T) {
	const origin = "atom://127.0.0.1:8080"
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	root := merkle.EmptyRoot()
	text, err := Sign(signer, origin, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "\n\n— "+origin+" ") {
		t.Fatalf("note format:\n%s", text)
	}
	cp, err := Parse(text, vkey)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != origin || cp.Size != 0 || !bytes.Equal(cp.Root, root) || cp.Note != text {
		t.Fatalf("%+v", cp)
	}
	// Wrong key.
	_, vkey2, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(text, vkey2); err == nil {
		t.Fatal("accepted wrong key")
	}
	// Tamper the size line.
	tampered := strings.Replace(text, "\n0\n", "\n1\n", 1)
	if _, err := Parse(tampered, vkey); err == nil {
		t.Fatal("accepted tampered note")
	}
	if _, _, _, err := ParseBody("not-a-body"); err == nil {
		t.Fatal("body")
	}
	if _, err := Sign(signer, "other", 0, root); err == nil {
		t.Fatal("origin mismatch")
	}
	sum := sha256.Sum256([]byte("root"))
	text, err = Sign(signer, origin, 2, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	cp, err = Parse(text, vkey)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 2 || !bytes.Equal(cp.Root, sum[:]) || codec.Encode(cp.Root) == "" {
		t.Fatal(cp)
	}
	_ = ed25519.PublicKeySize
}

func FuzzParseCheckpoint(f *testing.F) {
	const origin = "atom://fuzz"
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		f.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		f.Fatal(err)
	}
	good, err := Sign(signer, origin, 1, bytes.Repeat([]byte{0xab}, 32))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, vkey)
	f.Add("", "")
	f.Add("origin\n1\nAAAA\n", "not-a-key")
	f.Add(good, "bad+key")
	f.Fuzz(func(t *testing.T, noteText, vkey string) {
		if len(noteText) > 1<<20 {
			noteText = noteText[:1<<20]
		}
		if _, err := Parse(noteText, vkey); err == nil {
			return
		}
		_, _, _, _ = ParseBody(noteText)
	})
}
