package keys

import (
	"bytes"
	"testing"

	"github.com/ao3575911/atomhandle/internal/handle"
)

func TestAgentRoundTrip(t *testing.T) {
	home := t.TempDir()
	h, err := handle.Parse("@you/agent")
	if err != nil {
		t.Fatal(err)
	}
	k, created, err := LoadOrCreateAgent(home, h)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	again, created, err := LoadOrCreateAgent(home, h)
	if err != nil || created || !bytes.Equal(k, again) {
		t.Fatal(err, created)
	}
}
