package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func keygen(t *testing.T, dir, name, typ string, bits string) {
	t.Helper()
	args := []string{"-q", "-N", "", "-t", typ, "-f", filepath.Join(dir, name)}
	if bits != "" {
		args = append(args, "-b", bits)
	}
	if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen unavailable: %v %s", err, out)
	}
}

func TestAllHostKeysAdvertisedInOpenSSHOrder(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir, "hostkey", "ed25519", "")
	keygen(t, dir, "hostkey_rsa", "rsa", "3072")
	keygen(t, dir, "hostkey_ecdsa", "ecdsa", "256")

	keys := loadHostKeys(filepath.Join(dir, "hostkey"))
	l := serverKexInitWith(t, keys)
	// Exactly OpenSSH 8.9's list. The patched x/crypto (third_party/)
	// puts rsa-sha2-512 first; ssh-rsa (SHA-1) is dropped because 8.9 no
	// longer offers it.
	if want := "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"; l.HostKey != want {
		t.Errorf("host keys = %s, want %s", l.HostKey, want)
	}
}

func TestMissingOrBrokenExtraHostKeysAreSkipped(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir, "hostkey", "ed25519", "")
	// What a compose bind mount of a missing file leaves behind.
	os.Mkdir(filepath.Join(dir, "hostkey_rsa"), 0o755)

	keys := loadHostKeys(filepath.Join(dir, "hostkey"))
	if l := serverKexInitWith(t, keys); l.HostKey != "ssh-ed25519" {
		t.Errorf("host keys = %s, want ssh-ed25519 only", l.HostKey)
	}
}
