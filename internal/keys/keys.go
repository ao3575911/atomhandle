// Package keys stores Ed25519 seeds under the atom home directory.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/handle"
)

const fileHeader = "atom-ed25519-v1\n"

// ErrExists is returned when a key file is already present.
var ErrExists = errors.New("key already exists")

// ErrNotFound is returned when a key file is missing.
var ErrNotFound = errors.New("key not found")

// OwnerPath is the owner seed file.
func OwnerPath(home string) string {
	return filepath.Join(home, "owner.key")
}

// AgentPath is the per-handle agent seed file.
func AgentPath(home string, h handle.Handle) string {
	return filepath.Join(home, "agents", h.Owner, h.Name+".key")
}

// GenerateOwner writes a new owner key. It fails if one already exists.
func GenerateOwner(home string) (ed25519.PrivateKey, error) {
	return generateNew(OwnerPath(home))
}

// LoadOwner reads the owner key.
func LoadOwner(home string) (ed25519.PrivateKey, error) {
	return readKey(OwnerPath(home))
}

// LoadOrCreateOwner returns the owner key, creating it if absent.
func LoadOrCreateOwner(home string) (ed25519.PrivateKey, bool, error) {
	k, err := LoadOwner(home)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	k, err = GenerateOwner(home)
	if err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// LoadOrCreateAgent returns the agent key for h, creating it if absent.
func LoadOrCreateAgent(home string, h handle.Handle) (ed25519.PrivateKey, bool, error) {
	k, err := LoadAgent(home, h)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	k, err = generateNew(AgentPath(home, h))
	if err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// LoadAgent reads the agent key for h.
func LoadAgent(home string, h handle.Handle) (ed25519.PrivateKey, error) {
	return readKey(AgentPath(home, h))
}

func generateNew(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKey(path, priv.Seed()); err != nil {
		return nil, err
	}
	return priv, nil
}

func writeKey(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed size %d", len(seed))
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	body := fileHeader + codec.Encode(seed) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(body)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	return os.Chmod(path, 0o600)
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if err != nil {
		return nil, err
	}
	s := string(b)
	if !strings.HasPrefix(s, fileHeader) {
		return nil, fmt.Errorf("%s: bad key header", path)
	}
	rest := strings.TrimPrefix(s, fileHeader)
	if strings.Count(rest, "\n") != 1 || !strings.HasSuffix(rest, "\n") {
		return nil, fmt.Errorf("%s: bad key file", path)
	}
	line := strings.TrimSuffix(rest, "\n")
	seed, err := codec.DecodeFixed(line, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
