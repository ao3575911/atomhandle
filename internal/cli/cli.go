// Package cli implements the atom and atom-log commands.
package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ao3575911/atomhandle/internal/api"
	"github.com/ao3575911/atomhandle/internal/checkpoint"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/doc"
	"github.com/ao3575911/atomhandle/internal/handle"
	"github.com/ao3575911/atomhandle/internal/keys"
	"github.com/ao3575911/atomhandle/internal/logclient"
	"github.com/ao3575911/atomhandle/internal/merkle"
	"github.com/ao3575911/atomhandle/internal/passport"
	"github.com/ao3575911/atomhandle/internal/state"
	"github.com/ao3575911/atomhandle/internal/tlog"
)

// Version is the release version, overridable with -X.
var Version = "0.1.0"

const (
	// DefaultLogURL is the log atom claim talks to when --log is omitted.
	DefaultLogURL = "http://127.0.0.1:8080"
	// DefaultOrigin is the checkpoint origin used by atom serve.
	DefaultOrigin = "atom://127.0.0.1:8080"
	// DefaultAddr is the listen address used by atom serve.
	DefaultAddr = "127.0.0.1:8080"
)

// Env is the process environment a command runs in.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Args   []string
	Home   string
	Now    func() time.Time
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e Env) out() io.Writer {
	if e.Stdout != nil {
		return e.Stdout
	}
	return os.Stdout
}

func (e Env) err() io.Writer {
	if e.Stderr != nil {
		return e.Stderr
	}
	return os.Stderr
}

// Main runs atom with the process environment.
func Main(args []string) int {
	home, err := defaultHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "atom: %v\n", err)
		return 1
	}
	return Run(Env{Stdout: os.Stdout, Stderr: os.Stderr, Args: args, Home: home})
}

// LogMain runs atom-log (the server) with the process environment.
func LogMain(args []string) int {
	home, err := defaultHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "atom-log: %v\n", err)
		return 1
	}
	return Run(Env{Stdout: os.Stdout, Stderr: os.Stderr, Args: append([]string{"serve"}, args...), Home: home})
}

func defaultHome() (string, error) {
	if h := os.Getenv("ATOM_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".atom"), nil
}

// Run executes a command.
func Run(env Env) int {
	if len(env.Args) == 0 {
		fmt.Fprint(env.err(), usage)
		return 2
	}
	switch env.Args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(env.out(), usage)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintf(env.out(), "atom %s\n", Version)
		return 0
	case "keygen":
		return cmdKeygen(env, env.Args[1:])
	case "claim":
		return cmdClaim(env, env.Args[1:])
	case "sign":
		return cmdSign(env, env.Args[1:])
	case "verify":
		return cmdVerify(env, env.Args[1:])
	case "checkpoint":
		return cmdCheckpoint(env, env.Args[1:])
	case "serve":
		return cmdServe(env, env.Args[1:])
	case "log":
		if len(env.Args) < 2 || env.Args[1] != "serve" {
			fmt.Fprint(env.err(), usage)
			return 2
		}
		return cmdServe(env, env.Args[2:])
	default:
		fmt.Fprintf(env.err(), "atom: unknown command %q\n%s", env.Args[0], usage)
		return 2
	}
}

const usage = `atom — did:atom handles, verifiable offline

Usage:
  atom keygen
  atom claim <@owner/name> [--log URL] [--scopes a,b] [--expires 90d] [--out passport.json]
  atom sign --handle <@owner/name> [--out FILE.sig] FILE
  atom verify PASSPORT [--sig FILE.sig FILE] [--log-key KEY]
  atom checkpoint save --log URL
  atom serve [--addr ADDR] [--data DIR] [--origin ORIGIN] [--dev]
  atom log serve [--addr ADDR] [--data DIR] [--origin ORIGIN] [--dev]
  atom version

Default log URL: http://127.0.0.1:8080
Keys and pinned checkpoints: ~/.atom (override with ATOM_HOME)
`

func cmdKeygen(env Env, args []string) int {
	fs := newFlag("keygen", env)
	if err := fs.Parse(args); err != nil {
		return flagStatus(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprint(env.err(), "usage: atom keygen\n")
		return 2
	}
	priv, err := keys.GenerateOwner(env.Home)
	if err != nil {
		return fail(env, err)
	}
	pub := public(priv)
	fmt.Fprintf(env.out(), "public %s\nwrote %s\n", codec.Encode(pub), keys.OwnerPath(env.Home))
	return 0
}

func cmdClaim(env Env, args []string) int {
	fs := newFlag("claim", env)
	logURL := fs.String("log", DefaultLogURL, "log base URL")
	scopesFlag := fs.String("scopes", "", "comma-separated scopes")
	expires := fs.String("expires", "90d", "lifetime (90d, 12h, or RFC3339)")
	out := fs.String("out", "passport.json", "passport path")
	// The handle is documented before the flags. flag.FlagSet stops at the
	// first non-flag, so pull flags out and parse them first.
	if err := fs.Parse(flagsFirst(args, "log", "scopes", "expires", "out")); err != nil {
		return flagStatus(err)
	}
	if fs.NArg() != 1 {
		fmt.Fprint(env.err(), "usage: atom claim <@owner/name> [--log URL] [--scopes a,b] [--expires 90d] [--out passport.json]\n")
		return 2
	}
	h, err := handle.Parse(fs.Arg(0))
	if err != nil {
		return fail(env, err)
	}
	scopes, err := parseScopes(*scopesFlag)
	if err != nil {
		return fail(env, err)
	}
	created := env.now().Truncate(time.Second)
	expiry, err := parseExpires(created, *expires)
	if err != nil {
		return fail(env, err)
	}
	owner, createdOwner, err := keys.LoadOrCreateOwner(env.Home)
	if err != nil {
		return fail(env, err)
	}
	if createdOwner {
		fmt.Fprintf(env.err(), "generated owner key %s\n", keys.OwnerPath(env.Home))
	}
	agent, _, err := keys.LoadOrCreateAgent(env.Home, h)
	if err != nil {
		return fail(env, err)
	}
	signed, err := doc.Sign(owner, doc.Body{
		Handle:  h,
		Owner:   public(owner),
		Agents:  []ed25519.PublicKey{public(agent)},
		Scopes:  scopes,
		Created: created,
		Expiry:  expiry,
	})
	if err != nil {
		return fail(env, err)
	}
	client := logclient.New(*logURL)
	resp, err := client.Submit(signed.Raw)
	if err != nil {
		return fail(env, err)
	}
	cp, err := checkSubmit(signed.Raw, resp)
	if err != nil {
		return fail(env, err)
	}
	st, err := state.Open(env.Home)
	if err != nil {
		return fail(env, err)
	}
	if err := st.PinLogKey(cp.Origin, resp.LogKey); err != nil {
		return fail(env, err)
	}
	if err := observe(st, client, cp, resp.LogKey); err != nil {
		return fail(env, err)
	}
	bundle := &passport.Bundle{
		Version:        1,
		Document:       append([]byte(nil), signed.Raw...),
		Index:          resp.Index,
		TreeSize:       resp.TreeSize,
		LeafHash:       resp.LeafHash,
		InclusionProof: resp.InclusionProof,
		Checkpoint:     resp.Checkpoint,
		LogKey:         resp.LogKey,
	}
	if _, err := passport.Verify(bundle, resp.LogKey, env.now()); err != nil {
		return fail(env, err)
	}
	if err := passport.Write(*out, bundle); err != nil {
		return fail(env, err)
	}
	fmt.Fprintf(env.out(), "claimed %s\ndid %s\nindex %d\npassport %s\n", h, h.DID(), resp.Index, *out)
	return 0
}

func cmdSign(env Env, args []string) int {
	fs := newFlag("sign", env)
	handleStr := fs.String("handle", "", "handle (@owner/name)")
	out := fs.String("out", "", "signature path (default FILE.sig)")
	if err := fs.Parse(args); err != nil {
		return flagStatus(err)
	}
	if *handleStr == "" || fs.NArg() != 1 {
		fmt.Fprint(env.err(), "usage: atom sign --handle <@owner/name> [--out FILE.sig] FILE\n")
		return 2
	}
	h, err := handle.Parse(*handleStr)
	if err != nil {
		return fail(env, err)
	}
	agent, err := keys.LoadAgent(env.Home, h)
	if err != nil {
		return fail(env, fmt.Errorf("%w (run atom claim %s)", err, h))
	}
	file := fs.Arg(0)
	data, err := os.ReadFile(file)
	if err != nil {
		return fail(env, err)
	}
	sig, err := doc.SignArtifact(agent, h.String(), data)
	if err != nil {
		return fail(env, err)
	}
	sigPath := *out
	if sigPath == "" {
		sigPath = file + ".sig"
	}
	body := codec.Encode(sig) + "\n"
	if err := os.WriteFile(sigPath, []byte(body), 0o644); err != nil {
		return fail(env, err)
	}
	fmt.Fprintf(env.out(), "wrote %s\n", sigPath)
	return 0
}

func cmdVerify(env Env, args []string) int {
	passportPath, sigPath, dataPath, logKey, err := parseVerifyArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(env.out(), verifyUsage)
			return 0
		}
		fmt.Fprintf(env.err(), "atom: %v\n%s", err, verifyUsage)
		return 2
	}
	bundle, err := passport.Read(passportPath)
	if err != nil {
		return fail(env, err)
	}
	trusted := logKey
	var origin string
	if trusted == "" {
		origin, err = noteOrigin(bundle.Checkpoint)
		if err != nil {
			return fail(env, err)
		}
		st, err := state.Open(env.Home)
		if err != nil {
			return fail(env, err)
		}
		trusted, err = st.LogKey(origin)
		if err != nil {
			return fail(env, fmt.Errorf("%w; pass --log-key", err))
		}
	}
	res, err := passport.Verify(bundle, trusted, env.now())
	if err != nil {
		return fail(env, err)
	}
	st, err := state.Open(env.Home)
	if err != nil {
		return fail(env, err)
	}
	hist, err := st.History(res.Checkpoint.Origin, trusted)
	if err != nil {
		return fail(env, err)
	}
	latest, err := state.Check(res.Checkpoint, hist)
	if err != nil {
		return fail(env, err)
	}
	if sigPath != "" {
		sig, err := readSig(sigPath)
		if err != nil {
			return fail(env, err)
		}
		file, err := os.ReadFile(dataPath)
		if err != nil {
			return fail(env, err)
		}
		if err := res.Document.VerifyArtifact(file, sig); err != nil {
			return fail(env, err)
		}
	}
	fmt.Fprintf(env.out(), "ok %s\ndid %s\nexpires %s\nlog-size %d\n",
		res.Document.Handle, res.Document.Handle.DID(),
		res.Document.Expiry.Format(time.RFC3339), res.TreeSize)
	if latest > res.TreeSize {
		fmt.Fprintf(env.out(), "consistency %d -> %d\n", res.TreeSize, latest)
	}
	if sigPath != "" {
		fmt.Fprintln(env.out(), "artifact ok")
	}
	return 0
}

const verifyUsage = `usage: atom verify PASSPORT [--sig FILE.sig FILE] [--log-key KEY]
`

func cmdCheckpoint(env Env, args []string) int {
	if len(args) == 0 || args[0] != "save" {
		fmt.Fprint(env.err(), "usage: atom checkpoint save --log URL\n")
		return 2
	}
	fs := newFlag("checkpoint save", env)
	logURL := fs.String("log", DefaultLogURL, "log base URL")
	if err := fs.Parse(args[1:]); err != nil {
		return flagStatus(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprint(env.err(), "usage: atom checkpoint save --log URL\n")
		return 2
	}
	client := logclient.New(*logURL)
	resp, err := client.Checkpoint()
	if err != nil {
		return fail(env, err)
	}
	cp, err := checkpoint.Parse(resp.Checkpoint, resp.LogKey)
	if err != nil {
		return fail(env, err)
	}
	if resp.Origin != cp.Origin || resp.Size != cp.Size || resp.RootHash != codec.Encode(cp.Root) || resp.LogKey == "" {
		return fail(env, errors.New("checkpoint response does not match signed note"))
	}
	st, err := state.Open(env.Home)
	if err != nil {
		return fail(env, err)
	}
	if err := st.PinLogKey(cp.Origin, resp.LogKey); err != nil {
		return fail(env, err)
	}
	if cp.Size == 0 {
		fmt.Fprintf(env.out(), "pinned log key for %s (empty log)\n", cp.Origin)
		return 0
	}
	if err := observe(st, client, cp, resp.LogKey); err != nil {
		return fail(env, err)
	}
	fmt.Fprintf(env.out(), "pinned %s size %d\n", cp.Origin, cp.Size)
	return 0
}

func cmdServe(env Env, args []string) int {
	fs := newFlag("serve", env)
	addr := fs.String("addr", DefaultAddr, "listen address")
	data := fs.String("data", "", "data directory")
	origin := fs.String("origin", DefaultOrigin, "checkpoint origin")
	dev := fs.Bool("dev", false, "development defaults and request log")
	if err := fs.Parse(args); err != nil {
		return flagStatus(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprint(env.err(), "usage: atom serve [--addr ADDR] [--data DIR] [--origin ORIGIN] [--dev]\n")
		return 2
	}
	dataDir := *data
	explicitData := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "data" {
			explicitData = true
		}
	})
	if !explicitData {
		if *dev {
			dataDir = "atom-data"
		} else {
			dataDir = filepath.Join(env.Home, "server")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, env, *addr, dataDir, *origin, *dev); err != nil {
		return fail(env, err)
	}
	return 0
}

func serve(ctx context.Context, env Env, addr, dataDir, origin string, dev bool) error {
	lg, err := tlog.Open(dataDir, origin)
	if err != nil {
		return err
	}
	defer lg.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           lg.Handler(dev),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	fmt.Fprintf(env.out(), "listening on http://%s\norigin %s\ndata %s\nlog key %s\n", ln.Addr().String(), origin, dataDir, lg.LogKey())
	select {
	case <-ctx.Done():
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(cctx)
		return <-errc
	case err := <-errc:
		return err
	}
}

func checkSubmit(raw []byte, resp *api.SubmitResponse) (*checkpoint.Checkpoint, error) {
	cp, err := checkpoint.Parse(resp.Checkpoint, resp.LogKey)
	if err != nil {
		return nil, fmt.Errorf("log checkpoint: %w", err)
	}
	if cp.Size != resp.TreeSize || resp.TreeSize == 0 || resp.Index >= resp.TreeSize {
		return nil, errors.New("log response tree size")
	}
	leaf := merkle.LeafHash(raw)
	if codec.Encode(leaf) != resp.LeafHash {
		return nil, errors.New("log response leaf hash")
	}
	proof, err := decodeHashes(resp.InclusionProof)
	if err != nil {
		return nil, err
	}
	if err := merkle.VerifyInclusion(leaf, resp.Index, resp.TreeSize, proof, cp.Root); err != nil {
		return nil, fmt.Errorf("log inclusion proof: %w", err)
	}
	return cp, nil
}

func observe(st *state.Store, client *logclient.Client, cp *checkpoint.Checkpoint, trusted string) error {
	if cp.Size == 0 {
		return nil
	}
	hist, err := st.History(cp.Origin, trusted)
	if err != nil {
		return err
	}
	if len(hist) == 0 {
		return st.AppendCheckpoint(cp.Origin, trusted, cp, 0, nil)
	}
	last := hist[len(hist)-1]
	if cp.Size == last.Size {
		if !bytes.Equal(cp.Root, last.Root) {
			return fmt.Errorf("log equivocation at size %d", cp.Size)
		}
		return nil
	}
	if cp.Size < last.Size {
		return fmt.Errorf("log rolled back from %d to %d", last.Size, cp.Size)
	}
	proof, err := client.Consistency(last.Size, cp.Size)
	if err != nil {
		return err
	}
	if err := merkle.VerifyConsistency(last.Size, cp.Size, last.Root, cp.Root, proof); err != nil {
		return fmt.Errorf("refusing checkpoint: %w", err)
	}
	return st.AppendCheckpoint(cp.Origin, trusted, cp, last.Size, proof)
}

func noteOrigin(noteText string) (string, error) {
	i := strings.LastIndex(noteText, "\n\n")
	if i < 0 {
		return "", errors.New("malformed checkpoint")
	}
	origin, _, _, err := checkpoint.ParseBody(noteText[:i+1])
	if err != nil {
		return "", err
	}
	return origin, nil
}

func readSig(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.SignatureSize {
		return b, nil
	}
	sig, err := codec.DecodeFixed(strings.TrimSpace(string(b)), ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return sig, nil
}

func decodeHashes(ss []string) ([][]byte, error) {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		h, err := codec.DecodeFixed(s, 32)
		if err != nil {
			return nil, fmt.Errorf("proof: %w", err)
		}
		out[i] = h
	}
	return out, nil
}

func public(priv ed25519.PrivateKey) ed25519.PublicKey {
	pub := priv.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), pub...)
}

func parseScopes(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return []string{}, nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, errors.New("empty scope")
		}
		out = append(out, p)
	}
	return doc.NormalizeScopes(out)
}

func parseExpires(now time.Time, spec string) (time.Time, error) {
	now = now.UTC().Truncate(time.Second)
	if spec == "" {
		spec = "90d"
	}
	if t, err := time.Parse(time.RFC3339, spec); err == nil {
		t = t.UTC().Truncate(time.Second)
		if !t.After(now) {
			return time.Time{}, fmt.Errorf("expiry %s is not after %s", t.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		return t, nil
	}
	if len(spec) >= 2 {
		unit := spec[len(spec)-1]
		if unit == 'd' || unit == 'w' {
			n := 0
			for _, c := range spec[:len(spec)-1] {
				if c < '0' || c > '9' {
					return time.Time{}, fmt.Errorf("bad expiry %q", spec)
				}
				n = n*10 + int(c-'0')
				if n > 36500 {
					return time.Time{}, fmt.Errorf("bad expiry %q", spec)
				}
			}
			if n <= 0 {
				return time.Time{}, fmt.Errorf("bad expiry %q", spec)
			}
			days := n
			if unit == 'w' {
				days = n * 7
			}
			return now.AddDate(0, 0, days), nil
		}
	}
	d, err := time.ParseDuration(spec)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("bad expiry %q", spec)
	}
	return now.Add(d).UTC().Truncate(time.Second), nil
}

func parseVerifyArgs(args []string) (passportPath, sigPath, dataPath, logKey string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			return "", "", "", "", flag.ErrHelp
		case "--log-key":
			if i+1 >= len(args) {
				return "", "", "", "", errors.New("--log-key needs a value")
			}
			i++
			logKey = args[i]
		case "--sig":
			if i+2 >= len(args) {
				return "", "", "", "", errors.New("--sig needs FILE.sig and FILE")
			}
			sigPath = args[i+1]
			dataPath = args[i+2]
			i += 2
		default:
			if strings.HasPrefix(a, "-") {
				return "", "", "", "", fmt.Errorf("unknown flag %s", a)
			}
			if passportPath != "" {
				return "", "", "", "", fmt.Errorf("unexpected argument %s", a)
			}
			passportPath = a
		}
	}
	if passportPath == "" {
		return "", "", "", "", errors.New("passport path required")
	}
	if (sigPath == "") != (dataPath == "") {
		return "", "", "", "", errors.New("--sig needs FILE.sig and FILE")
	}
	return passportPath, sigPath, dataPath, logKey, nil
}

// flagsFirst moves flags (and their values) ahead of positional arguments.
func flagsFirst(args []string, valued ...string) []string {
	takesValue := map[string]bool{}
	for _, name := range valued {
		takesValue[name] = true
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		flags = append(flags, a)
		if takesValue[name] && !strings.Contains(a, "=") {
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, pos...)
}

func newFlag(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.err())
	return fs
}

func flagStatus(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func fail(env Env, err error) int {
	fmt.Fprintf(env.err(), "atom: %v\n", err)
	return 1
}
