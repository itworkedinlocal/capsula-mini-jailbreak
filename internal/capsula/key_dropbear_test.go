package capsula

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDropbearKeyCodec(t *testing.T) {
	key, err := newDropbearKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	pub, err := dropbearPublic(key)
	if err != nil || !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatal(pub, err)
	}
	bad := append([]byte(nil), key...)
	bad[82] ^= 1
	for _, b := range [][]byte{nil, key[:82], append(key, 0), bad} {
		if _, err = dropbearPublic(b); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if runtime.GOOS != "linux" {
		return
	}
	// The pinned, independently built Dropbear must read the Go-generated key.
	path := filepath.Join(t.TempDir(), "hostkey")
	if err = os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	r := sourceResources(t)
	out, err := r.Native("dropbearmulti", []string{"dropbearkey", "-y", "-f", path}, nil)
	if err != nil || !strings.Contains(string(out), pub) {
		t.Fatalf("native Dropbear rejected key: %s %v", out, err)
	}
	native := filepath.Join(t.TempDir(), "native")
	if _, err = r.Native("dropbearmulti", []string{"dropbearkey", "-t", "ed25519", "-f", native}, nil); err != nil {
		t.Fatal(err)
	}
	key2, err := os.ReadFile(native)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key2)
	pub2, err := dropbearPublic(key2)
	if err != nil {
		t.Fatal(err)
	}
	out, err = r.Native("dropbearmulti", []string{"dropbearkey", "-y", "-f", native}, nil)
	if err != nil || !strings.Contains(string(out), pub2) {
		t.Fatal("native key decode mismatch", err)
	}
}
