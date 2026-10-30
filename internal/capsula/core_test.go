package capsula

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/u-root/u-root/pkg/cpio"
	"github.com/u-root/u-root/pkg/dt"
)

func sourceResources(t *testing.T) Resources {
	t.Helper()
	if root := os.Getenv("CAPSULA_TEST_RESOURCE_ROOT"); root != "" {
		return Resources{root, filepath.Join(root, "fastfetch.jsonc")}
	}
	root, e := filepath.Abs("../../resources")
	if e != nil {
		t.Fatal(e)
	}
	if !Exists(filepath.Join(root, "ramboot", "Image")) {
		t.Fatalf("missing runtime resource from repository: %s", filepath.Join(root, "ramboot", "Image"))
	}
	return Resources{root, filepath.Join(root, "fastfetch.jsonc")}
}
func TestPolicies(t *testing.T) {
	for _, mode := range []string{"simple", "fast", "expert"} {
		p, e := NewPolicy(mode, nil)
		if e != nil || p.Validate() != nil {
			t.Fatalf("%s: %v", mode, e)
		}
		if mode == "fast" {
			for _, stage := range []string{"backup", "full-scan", "data-compare", "probe", "probe-audit"} {
				if p.Enabled(stage) {
					t.Fatal("fast enabled", stage)
				}
			}
			for _, stage := range []string{"package-hash", "space", "conflicts", "post-verify"} {
				if !p.Enabled(stage) {
					t.Fatal("fast skipped", stage)
				}
			}
		}
	}
	for _, s := range Stages {
		p, e := NewPolicy("expert", []string{s})
		if e != nil || p.Enabled(s) || p.Validate() != nil {
			t.Fatalf("skip %s: %v", s, e)
		}
	}
	if _, e := NewPolicy("simple", []string{"space"}); e == nil {
		t.Fatal("simple override")
	}
	if _, e := NewPolicy("expert", []string{"device-identity"}); e == nil {
		t.Fatal("hard guard skipped")
	}
	p, _ := NewPolicy("expert", []string{"post-verify"})
	if p.Enabled("probe-audit") {
		t.Fatal("audit without post-read")
	}
}
func TestPythonCanonicalSealing(t *testing.T) {
	v := map[string]any{"кириллица": "пароль 😀\x7f <>&\n", "n": json.Number("1234567890123456789"), "list": []any{true, nil, 0}}
	b, e := Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"list":[true,null,0],"n":1234567890123456789,"\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430":"\u043f\u0430\u0440\u043e\u043b\u044c \ud83d\ude00\u007f <>&\n"}`
	if string(b) != want {
		t.Fatalf("%s != %s", b, want)
	}
	p := filepath.Join(t.TempDir(), "state.json")
	if e = SaveSealed(p, v); e != nil {
		t.Fatal(e)
	}
	var got map[string]any
	if e = ReadSealed(p, &got); e != nil {
		t.Fatal(e)
	}
	if got["кириллица"] != v["кириллица"] {
		t.Fatal("Unicode lost")
	}
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{} {}`} {
		if UniqueJSON([]byte(raw)) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
func TestPrivateStateRejectsLinksAndCorruption(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "state")
	if e := SaveSealed(p, map[string]any{"a": 1}); e != nil {
		t.Fatal(e)
	}
	body, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(body, []byte(`"a": 1`), []byte(`"a": 2`), 1), 0600)
	var v any
	if ReadSealed(p, &v) == nil {
		t.Fatal("tamper accepted")
	}
	_ = os.Symlink(p, filepath.Join(d, "link"))
	if ReadPrivate(filepath.Join(d, "link"), &v) == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := SafeJoin(d, "../outside"); e == nil {
		t.Fatal("traversal accepted")
	}
}
func TestPasswordBoundaries(t *testing.T) {
	for _, b := range [][]byte{[]byte("x"), bytes.Repeat([]byte{'x'}, 512), bytes.Repeat([]byte("я"), 256)} {
		if e := ValidatePassword(b); e != nil {
			t.Fatal(e)
		}
	}
	for _, b := range [][]byte{nil, bytes.Repeat([]byte{'x'}, 513), []byte("a\nb"), []byte("\x00"), {0xff}} {
		if ValidatePassword(b) == nil {
			t.Fatal("invalid password accepted")
		}
	}
}
func TestDeviceExportUsesLiveKernelView(t *testing.T) {
	var out strings.Builder
	for _, n := range lowerNames {
		b := []byte("stock " + n)
		fmt.Fprintf(&out, "FILE /stock%s %s %s\n", n, SHA(b), base64.StdEncoding.EncodeToString(b))
	}
	out.WriteString("KERNEL 4.9.113\nDEVICE_STOCK\nDEVICE_CLEAN\n")
	b, e := ParseDeviceExport(out.String())
	if e != nil || b.Installed || len(b.Files) != 4 {
		t.Fatal(e)
	}
	if _, e = ParseDeviceExport(strings.Replace(out.String(), "DEVICE_CLEAN", "", 1)); e == nil {
		t.Fatal("unclean export accepted")
	}
	if _, e = ParseDeviceExport(strings.Replace(out.String(), "FILE /stock/etc/passwd", "FILE /stock/../../secret", 1)); e == nil {
		t.Fatal("foreign export accepted")
	}
}
func fixturePackage(t *testing.T, id, dir string) (*Manifest, error) {
	t.Helper()
	if e := PrivateDir(dir); e != nil {
		return nil, e
	}
	m := &Manifest{Version: "9.8.7-fixture", Schema: 2, Architecture: "aarch64", Identity: id, Files: map[string]FileRecord{}, Lower: map[string]string{}, Kernels: []string{"4.9.113"}}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	var index, hashes, lower strings.Builder
	var total int64
	for _, n := range coreNames {
		b := []byte("fixture " + n)
		row := FileRecord{int64(len(b)), SHA(b), 0755, 0, 0}
		m.Files[n] = row
		total += row.Bytes
		if e := tw.WriteHeader(&tar.Header{Name: n, Size: row.Bytes, Mode: row.Mode, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			return nil, e
		}
		if _, e := tw.Write(b); e != nil {
			return nil, e
		}
		fmt.Fprintf(&index, "%04o %s %s\n", row.Mode, row.SHA, n)
		fmt.Fprintf(&hashes, "%s  %s\n", row.SHA, n)
	}
	if e := tw.Close(); e != nil {
		return nil, e
	}
	m.ArchiveSHA = SHA(archive.Bytes())
	for _, n := range lowerNames {
		m.Lower[n] = SHA([]byte(n))
		fmt.Fprintf(&lower, "%s  /stock%s\n", m.Lower[n], n)
	}
	for n, b := range map[string][]byte{"overlay-files.tar": archive.Bytes(), "files.tsv": []byte(index.String()), "files.sha256": []byte(hashes.String()), "lower.sha256": []byte(lower.String()), "payload-bytes": []byte(fmt.Sprint(total) + "\n"), "server-hostkey.pub": []byte("fixture\n")} {
		if e := os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			return nil, e
		}
	}
	return m, AtomicJSON(filepath.Join(dir, "manifest.json"), m)
}
func TestPackageShapeAlwaysEnforcedAndHashSkippable(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 64)
	if _, e := fixturePackage(t, id, dir); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidatePackage(dir, id, true); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "overlay-files.tar")
	b, _ := os.ReadFile(p)
	b[512] ^= 1
	_ = os.WriteFile(p, b, 0600)
	if _, e := ValidatePackage(dir, id, true); e == nil {
		t.Fatal("hash mismatch accepted")
	}
	if _, e := ValidatePackage(dir, id, false); e != nil {
		t.Fatal("explicit hash skip failed", e)
	}
	for _, n := range []string{"../secret", "/etc/shadow", "etc//shadow", "usr/lib/capsula-root/../../etc/passwd", "usr/lib/capsula-root/evil\\path", "bootloader"} {
		if SafePackagePath(n) == nil {
			t.Fatal("unsafe member accepted", n)
		}
	}
}
func TestRAMBundleROAndDataOnly(t *testing.T) {
	r := sourceResources(t)
	p := testProfile(t)
	simple, _ := NewPolicy("simple", nil)
	fast, _ := NewPolicy("fast", nil)
	for _, o := range []RAMOptions{{Policy: simple}, {Profile: &p, Policy: fast}, {Profile: &p, Policy: fast, Writable: true}} {
		folder := t.TempDir()
		o.Slot = "b"
		b, e := BuildRAM(r, folder, o)
		if e != nil {
			t.Fatal(e)
		}
		blob, _ := os.ReadFile(b.Assets[1].Path)
		tree, e := ReadTree(blob)
		if e != nil {
			t.Fatal(e)
		}
		writable := []string{}
		_ = tree.RootNode.Walk(func(n *dt.Node) error {
			if strings.HasPrefix(n.Name, "partition@") && len(prop(n, "label")) > 0 && len(prop(n, "reg")) > 0 {
				if _, ok := n.LookProperty("read-only"); !ok {
					writable = append(writable, string(prop(n, "label")))
				}
			}
			return nil
		})
		if o.Writable {
			if len(writable) != 1 || writable[0] != "data\x00" {
				t.Fatal("wrong write scope", writable)
			}
		} else if len(writable) > 0 {
			t.Fatal("RO has writable partition")
		}
		image, _ := os.ReadFile(b.Assets[2].Path)
		gz, e := gzip.NewReader(bytes.NewReader(image[64:]))
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(gz)
		gz.Close()
		if e != nil {
			t.Fatal(e)
		}
		members := map[string]bool{}
		rr := cpio.Newc.Reader(bytes.NewReader(body))
		for {
			rec, e := rr.ReadRecord()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			members[rec.Name] = true
		}
		if members["capsula-control"] != o.Writable {
			t.Fatal("wrong installer inclusion")
		}
		if !members["capsula-ram-restart"] || !strings.Contains(strings.Join(b.Words, " "), "reboot=cold") {
			t.Fatal("missing guarded restart helper or cold reboot policy")
		}
		if o.Profile != nil && !members["capsula-inspect-device"] {
			t.Fatal("missing kernel export")
		}
		image[len(image)-1] ^= 1
		_ = os.WriteFile(b.Assets[2].Path, image, 0600)
		if ValidateRAM(r, b, o.Profile, o.Writable) == nil {
			t.Fatal("tampered initrd accepted")
		}
	}
}

func TestRollbackRAMNeedsNoHostProbeReceipt(t *testing.T) {
	r := sourceResources(t)
	p := testProfile(t)
	policy, _ := NewPolicy("simple", nil)
	for _, token := range []string{"", strings.Repeat("b", 64)} {
		if _, err := BuildRAM(r, t.TempDir(), RAMOptions{Operation: "rollback", Profile: &p, Policy: policy, Writable: true, Slot: "b", Expected: strings.Repeat("a", 64), Token: token}); err != nil {
			t.Fatal("rollback still requires host proof", err)
		}
	}
	if _, err := BuildRAM(r, t.TempDir(), RAMOptions{Operation: "probe", Profile: &p, Policy: policy, Writable: true, Slot: "b", Expected: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("new probe without token accepted")
	}
}

func TestRollbackReportsPreservedUserDirectories(t *testing.T) {
	p := testProfile(t)
	part, _ := p.Part("data")
	policy, _ := NewPolicy("fast", nil)
	body := fmt.Sprintf("PRESERVED_DIRECTORY usr/lib/capsula-root\nROLLBACK_REMOUNT_VERIFIED\nPROBE_REMOVED\nOVERLAY_ROLLED_BACK\ngood_blocks=%d bad_blocks=0 bytes=%d corrected_delta=0 failed_delta=0\n%s  /run/capsula-data.bin\nSTORAGE_CLEAN\n", part.Logical/Erase, part.Logical, strings.Repeat("a", 64))
	evidence, err := ParseStorage(body, "rollback", "", "", p, policy)
	if err != nil || len(evidence.PreservedDirectories) != 1 || evidence.PreservedDirectories[0] != "usr/lib/capsula-root" {
		t.Fatal("lost preserved paths", err)
	}
	if _, err := ParseStorage(strings.Replace(body, "usr/lib/capsula-root", "../../etc", 1), "rollback", "", "", p, policy); err == nil {
		t.Fatal("unsafe preserved path accepted")
	}
}
