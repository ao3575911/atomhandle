package state

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/ao3575911/atomhandle/internal/checkpoint"
)

func TestCheckEquivocationAndLink(t *testing.T) {
	const origin = "atom://state"
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	root1 := bytes.Repeat([]byte{1}, 32)
	root2 := bytes.Repeat([]byte{2}, 32)
	note1, err := checkpoint.Sign(signer, origin, 1, root1)
	if err != nil {
		t.Fatal(err)
	}
	cp1, err := checkpoint.Parse(note1, vkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(cp1, nil); err != nil {
		t.Fatal(err)
	}
	bad := []Record{{Size: 1, Root: root2, Note: note1}}
	if _, err := Check(cp1, bad); err == nil || !strings.Contains(err.Error(), "equivocation") {
		t.Fatalf("got %v", err)
	}
	newer := []Record{{Size: 2, Root: root2, Note: note1}}
	if _, err := Check(cp1, newer); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("got %v", err)
	}
	_ = vkey
}
