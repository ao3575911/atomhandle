package cli

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ao3575911/atomhandle/internal/doc"
	"github.com/ao3575911/atomhandle/internal/keys"
	"github.com/ao3575911/atomhandle/internal/passport"
	"github.com/ao3575911/atomhandle/internal/tlog"
)

func TestClaimSignVerify(t *testing.T) {
	home := t.TempDir()
	data := t.TempDir()
	lg, err := tlog.Open(data, "atom://cli")
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()
	srv := httptest.NewServer(lg.Handler(false))
	defer srv.Close()

	dir := t.TempDir()
	pass1 := filepath.Join(dir, "passport.json")
	pass2 := filepath.Join(dir, "other.json")
	msg := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msg, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := msg + ".sig"

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	env := Env{Stdout: stdout, Stderr: stderr, Home: home}
	run := func(args ...string) int {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		env.Args = args
		return Run(env)
	}
	if code := run("claim", "@you/agent", "--log", srv.URL, "--scopes", "b,a", "--out", pass1); code != 0 {
		t.Fatalf("claim: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "claimed @you/agent") || !strings.Contains(stdout.String(), "did did:atom:you/agent") {
		t.Fatalf("stdout %s", stdout.String())
	}
	b, err := passport.Read(pass1)
	if err != nil {
		t.Fatal(err)
	}
	d, err := doc.Parse(b.Document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Scopes, ",") != "a,b" {
		t.Fatalf("scopes %v", d.Scopes)
	}
	if code := run("claim", "@you/agent", "--log", srv.URL, "--out", pass1); code == 0 {
		t.Fatal("duplicate claim succeeded")
	}
	if !strings.Contains(stderr.String(), "already claimed") {
		t.Fatalf("stderr %s", stderr.String())
	}
	if code := run("sign", "--handle", "@you/agent", "--out", sig, msg); code != 0 {
		t.Fatalf("sign: %d %s", code, stderr.String())
	}
	if code := run("verify", pass1, "--sig", sig, msg); code != 0 {
		t.Fatalf("verify: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "artifact ok") {
		t.Fatalf("stdout %s", stdout.String())
	}
	if err := os.WriteFile(msg, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run("verify", pass1, "--sig", sig, msg); code == 0 {
		t.Fatal("tampered artifact verified")
	}
	if err := os.WriteFile(msg, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run("claim", "@you/other", "--log", srv.URL, "--expires", "10d", "--out", pass2); code != 0 {
		t.Fatalf("claim2: %d %s", code, stderr.String())
	}
	if code := run("verify", pass1); code != 0 {
		t.Fatalf("verify after second claim: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "consistency 1 -> 2") {
		t.Fatalf("stdout %s", stdout.String())
	}
	if code := run("verify", pass1, "--log-key", b.LogKey, "--sig", sig, msg); code != 0 {
		t.Fatalf("verify log-key: %d %s", code, stderr.String())
	}
	if code := run("verify", pass1, "--log-key", "not-a-key"); code == 0 {
		t.Fatal("bad log key accepted")
	}
	if code := run("checkpoint", "save", "--log", srv.URL); code != 0 {
		t.Fatalf("checkpoint: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "size 2") {
		t.Fatalf("stdout %s", stdout.String())
	}

	// Expired documents are rejected by the log.
	oldHome := t.TempDir()
	env.Home = oldHome
	env.Now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	if code := run("claim", "@you/stale", "--log", srv.URL, "--expires", "1h", "--out", filepath.Join(dir, "stale.json")); code == 0 {
		t.Fatal("expired claim accepted")
	}
}

func TestKeygenPermissions(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(Env{Stdout: &stdout, Stderr: &stderr, Home: home, Args: []string{"keygen"}})
	if code != 0 {
		t.Fatal(stderr.String())
	}
	fi, err := os.Stat(keys.OwnerPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	code = Run(Env{Stdout: &stdout, Stderr: &stderr, Home: home, Args: []string{"keygen"}})
	if code == 0 {
		t.Fatal("second keygen succeeded")
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if Run(Env{Stdout: &stdout, Stderr: &stderr, Args: nil}) != 2 {
		t.Fatal("no args")
	}
	stdout.Reset()
	if Run(Env{Stdout: &stdout, Stderr: &stderr, Args: []string{"help"}}) != 0 {
		t.Fatal("help")
	}
	if !strings.Contains(stdout.String(), "atom claim") {
		t.Fatal(stdout.String())
	}
	stdout.Reset()
	if Run(Env{Stdout: &stdout, Stderr: &stderr, Args: []string{"version"}}) != 0 {
		t.Fatal("version")
	}
	if !strings.Contains(stdout.String(), "0.1.0") {
		t.Fatal(stdout.String())
	}
}
