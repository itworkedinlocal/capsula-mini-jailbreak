package capsula

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/u-root/u-root/pkg/dt"
)

func testTree() *dt.FDT {
	root := dt.NewNode("", dt.WithProperty(dt.PropertyString("compatible", "amlogic,axg")))
	nand := dt.NewNode("nand", dt.WithProperty(dt.PropertyString("compatible", "aml_mtd_nand"), dt.Property{Name: "fip_size", Value: []byte{0, 0x20, 0, 0}}))
	parts := dt.NewNode("nand_partition")
	for _, name := range NormalNames {
		size := int64(Erase)
		if name == "tpl" || name == "data" {
			size = 0
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(size))
		parts.Children = append(parts.Children, dt.NewNode(name, dt.WithProperty(dt.Property{Name: "size", Value: b}, dt.Property{Name: "offset", Value: []byte{255, 255, 255, 255, 255, 255, 255, 255}})))
	}
	nand.Children = append(nand.Children, parts)
	root.Children = append(root.Children, nand)
	return &dt.FDT{RootNode: root}
}
func testProfile(t *testing.T) Profile {
	t.Helper()
	layout, e := LayoutFromTree(testTree())
	if e != nil {
		t.Fatal(e)
	}
	p, e := PhysicalProfile(strings.Repeat("a", 64), Geometry{0x8000000, Erase, 2048, 64}, []int{}, layout)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func sparseFile(path string, size int64, first byte) (string, error) {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	if _, e = f.Write([]byte{first}); e == nil {
		e = f.Truncate(size)
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	return path, ce
}
func zeroSHA(size int64, first byte) string {
	h := sha256.New()
	h.Write([]byte{first})
	_, _ = io.CopyN(h, zeroReader{}, size-1)
	return hex.EncodeToString(h.Sum(nil))
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

type model struct {
	p                     Profile
	layout                Layout
	tree                  *dt.FDT
	id                    string
	folder                string
	events                []string
	last                  RAMOptions
	data                  byte
	misc                  byte
	probe                 string
	installed             bool
	manifest              *Manifest
	key                   []byte
	hash                  []byte
	credentialError       bool
	bootEnv               map[string]string
	restarted             bool
	restartDirty          bool
	restartLostACK        bool
	restartTimeouts       int
	restartWrongIdentity  bool
	restartDirtyOnTimeout bool
	restartSlot           string
	restartCount          int
	corrupt               bool
	badChanged            bool
}

func newModel(t *testing.T) *model {
	t.Helper()
	m := &model{tree: testTree()}
	m.layout, _ = LayoutFromTree(m.tree)
	keys := make([]byte, 0x100000)
	for i := range keys {
		keys[i] = byte(i)
	}
	m.id = SHA(append([]byte("Capsula A113X keys identity v1\x00"), keys...))
	m.p = testProfile(t)
	m.p.Identity = m.id
	return m
}
func (m *model) SetFolder(p string) error { m.folder = p; return PrivateDir(p) }
func (m *model) Wait(time.Duration) error {
	m.events = append(m.events, "wait")
	m.misc++
	if m.restarted && m.restartTimeouts > 0 {
		m.restartTimeouts--
		if m.restartDirtyOnTimeout {
			m.restartDirty = true
		}
		return ErrLoaderTimeout
	}
	return nil
}
func (m *model) Metadata() (map[string]string, *dt.FDT, string, error) {
	slot := "b"
	if m.restartCount >= 2 && m.restartSlot != "" {
		slot = m.restartSlot
	}
	return m.bootEnv, m.tree, slot, nil
}
func (m *model) Configure(g Geometry) error { return g.Validate() }
func (m *model) ReadReserved(off, size int64, file string) (string, error) {
	p := filepath.Join(m.folder, file)
	if off == Reserved["keys"][0] {
		b := make([]byte, size)
		for i := range b {
			b[i] = byte(i)
		}
		if m.restarted && m.restartWrongIdentity {
			b[0] ^= 1
		}
		return p, os.WriteFile(p, b, 0600)
	}
	return sparseFile(p, size, 0)
}
func (m *model) ReadStore(name string, size int64, file string) (string, error) {
	m.events = append(m.events, "read-"+name)
	first := byte(0)
	if name == "data" {
		first = m.data
	}
	if name == "misc" {
		first = m.misc
	}
	return sparseFile(filepath.Join(m.folder, file), size, first)
}
func (m *model) ReadRaw(file string, _ func(string)) (string, error) {
	m.events = append(m.events, "raw")
	b := byte(0)
	if strings.Contains(file, "1") {
		b = 1
	}
	return sparseFile(filepath.Join(m.folder, file), m.p.Geometry.Size/2048*2112, b)
}
func (m *model) Boot(RAMBundle) error { m.events = append(m.events, "boot"); return nil }
func (m *model) Close()               { m.events = append(m.events, "close") }
func (m *model) scan(full bool) string {
	var out strings.Builder
	b, _ := json.Marshal(map[string]any{"kind": "geometry", "size": m.p.Geometry.Size, "erasesize": Erase, "writesize": 2048, "oobsize": 64})
	out.Write(b)
	out.WriteByte('\n')
	for block := 0; int64(block) < m.p.Geometry.Size/Erase; block++ {
		bad := m.badChanged && block == 100
		row := map[string]any{"kind": "block", "block": block, "bad": bad}
		if full && block >= 64 && !bad {
			first := byte(0)
			for _, p := range m.p.Parts {
				if p.Offset/Erase == int64(block) {
					if p.Name == "misc" {
						first = m.misc
					}
					if p.Name == "data" {
						first = m.data
					}
				}
			}
			hash := zeroSHA(Erase, first)
			if m.corrupt && block == 64 {
				hash = strings.Repeat("f", 64)
			}
			row["sha256"] = hash
			row["corrected"] = 1
			row["failed"] = 0
		}
		b, _ := json.Marshal(row)
		out.Write(b)
		out.WriteByte('\n')
	}
	mode := "metadata"
	if full {
		mode = "scan"
	}
	fmt.Fprintf(&out, "{\"kind\":\"end\",\"blocks\":%d,\"mode\":%q}\n", m.p.Geometry.Size/Erase, mode)
	return out.String()
}
func (m *model) Console(op, folder, nonce string, _ time.Duration) (string, error) {
	m.events = append(m.events, op)
	switch op {
	case "restart-check":
		if m.restartDirty {
			return "", fmt.Errorf("REFUSED: storage still attached")
		}
		return "RESTART_READY\n", nil
	case "restart":
		m.restarted = true
		m.restartCount++
		if m.restartLostACK {
			return "", fmt.Errorf("console disconnected before ACK")
		}
		return "RESTART_ARMED\n", nil
	case "metadata", "scan":
		return m.scan(op == "scan"), nil
	case "inspect", "credentials":
		if op == "credentials" && m.credentialError {
			return "", fmt.Errorf("invalid credential fixture")
		}
		var out strings.Builder
		for _, n := range lowerNames {
			data := []byte(n)
			fmt.Fprintf(&out, "FILE /stock%s %s %s\n", n, SHA(data), base64.StdEncoding.EncodeToString(data))
		}
		if m.installed {
			b, _ := json.Marshal(m.manifest)
			for name, data := range map[string][]byte{"manifest.json": b, "state": []byte("active\n"), "files.tsv": modelIndex(m.manifest)} {
				fmt.Fprintf(&out, "FILE /data/.capsula-root-state/%s %s %s\n", name, SHA(data), base64.StdEncoding.EncodeToString(data))
			}

			out.WriteString("DEVICE_INSTALLED\n")
			if op == "credentials" {
				for name, data := range map[string][]byte{"etc/capsula-root/hostkey": m.key, "etc/shadow": append(append([]byte("root:"), m.hash...), []byte(":0:0:99999:7:::\n")...)} {
					fmt.Fprintf(&out, "FILE /data/overlay/upper/%s %s %s\n", name, SHA(data), base64.StdEncoding.EncodeToString(data))
				}
			}
		} else {
			out.WriteString("DEVICE_STOCK\n")
		}
		if m.probe != "" {
			b := []byte(m.probe + "\n")
			fmt.Fprintf(&out, "FILE /data/.capsula-root-probe %s %s\n", SHA(b), base64.StdEncoding.EncodeToString(b))
		}
		out.WriteString("KERNEL 4.9.113\nDEVICE_CLEAN\n")
		return out.String(), nil
	case "stock":
		var out strings.Builder
		for _, n := range lowerNames {
			fmt.Fprintf(&out, "%s  /stock%s\n", SHA([]byte(n)), n)
		}
		out.WriteString("STOCK_CLEAN\n")
		return out.String(), nil
	}
	var out strings.Builder
	data, _ := m.p.Part("data")
	stats := fmt.Sprintf("good_blocks=%d bad_blocks=0 bytes=%d corrected_delta=1 failed_delta=0\n", data.Logical/Erase, data.Logical)
	p := m.last.Policy
	if p.Enabled("data-compare") {
		out.WriteString(stats)
		out.WriteString("DATA_MATCH " + m.last.Expected + "\n")
	} else {
		out.WriteString("SKIPPED data-compare\n")
	}
	marker := ""
	switch op {
	case "probe", "probe-check":
		m.probe = m.last.Token
		marker = "PROBE_PERSISTED"
		out.WriteString("PROBE_TOKEN " + SHA([]byte(m.probe+"\n")) + "\n")
	case "install", "refresh":
		m.installed = true
		marker = "OVERLAY_ACTIVATED"
		out.WriteString("INSTALL_REMOUNT_VERIFIED\n")
		m.manifest, _ = ValidatePackage(m.last.Package, m.id, true)
	case "rollback":
		m.installed = false
		m.probe = ""
		marker = "OVERLAY_ROLLED_BACK"
		out.WriteString("ROLLBACK_REMOUNT_VERIFIED\nPROBE_REMOVED\n")
	default:
		return "", fmt.Errorf("unknown model op")
	}
	m.data++
	out.WriteString(marker + "\n")
	if p.Enabled("post-verify") {
		out.WriteString(stats)
		out.WriteString(zeroSHA(data.Logical, m.data) + "  /run/capsula-data.bin\n")
	}
	out.WriteString("STORAGE_CLEAN\n")
	return out.String(), nil
}
func modelBackend(t *testing.T, mode string) (*Backend, *model) {
	t.Helper()
	store, e := NewStore(filepath.Join(t.TempDir(), "devices"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewPolicy(mode, nil)
	if e != nil {
		t.Fatal(e)
	}
	m := newModel(t)
	b := &Backend{Ctx: context.Background(), Store: store, Policy: p, Resources: sourceResources(t), NewTransport: func(_ context.Context, _ Resources, folder string) (Transport, error) {
		m.folder = folder
		return m, nil
	}, RAMBuilder: func(_ Resources, _ string, o RAMOptions) (RAMBundle, error) {
		m.last = o
		return RAMBundle{Nonce: strings.Repeat("a", 64)}, nil
	}, Reconnect: func(string) error { return nil }, Notify: func(string) {}, Password: func() ([]byte, error) { return []byte("fixture"), nil }, PackageBuilder: func(_ Resources, folder, device, id string, _ StockBundle, _ func() ([]byte, error), _ bool) (*Manifest, error) {
		creds := filepath.Join(device, "credentials")
		_ = PrivateDir(creds)
		if !Exists(filepath.Join(creds, "hostkey")) {
			if _, err := bNativeKey(sourceResources(t), filepath.Join(creds, "hostkey")); err != nil {
				return nil, err
			}
		}
		if !Exists(filepath.Join(creds, "root-password.hash")) {
			_ = os.WriteFile(filepath.Join(creds, "root-password.hash"), []byte("$6$rounds=100000$0123456789abcdef$"+strings.Repeat("A", 86)), 0600)
		}
		m.key, _ = os.ReadFile(filepath.Join(creds, "hostkey"))
		m.hash, _ = os.ReadFile(filepath.Join(creds, "root-password.hash"))
		manifest, err := fixturePackage(t, id, folder)
		if err != nil {
			return nil, err
		}
		pub, err := publicHostKey(sourceResources(t), filepath.Join(creds, "hostkey"))
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(filepath.Join(folder, "server-hostkey.pub"), []byte(pub+"\n"), 0600)
		return manifest, err
	}}
	return b, m
}
func TestFastFreshEnrollmentHasNoBackupScanSnapshotsOrProbe(t *testing.T) {
	b, m := modelBackend(t, "fast")
	out, e := b.Execute("root", false)
	if e != nil {
		t.Fatal(e)
	}
	if !out.InstallationCompleted || !out.StorageClean {
		t.Fatal("not installed")
	}
	for _, op := range m.events {
		if op == "raw" || op == "scan" || strings.HasPrefix(op, "read-") || op == "probe" {
			t.Fatal("fast performed", op)
		}
	}
	d, _ := b.Store.Device(m.id)
	if Exists(filepath.Join(d, "nand-map.json")) {
		t.Fatal("metadata was mislabeled verified backup")
	}
	if !Exists(filepath.Join(d, "device-profile.json")) {
		t.Fatal("no metadata profile")
	}
	if out.Stages["backup"].Status != "skipped" {
		t.Fatal("fake backup result")
	}
}
func TestSimpleBackupComparesAfterLoaderMiscChanges(t *testing.T) {
	b, m := modelBackend(t, "simple")
	out, e := b.Execute("root", false)
	if e != nil {
		t.Fatal(e)
	}
	if !out.InstallationCompleted {
		t.Fatal("not installed")
	}
	lastRaw, scan, probe, audit, install := -1, -1, -1, -1, -1
	for i, op := range m.events {
		switch op {
		case "raw":
			lastRaw = i
		case "scan":
			scan = i
		case "probe":
			probe = i
		case "install":
			install = i
		case "read-data":
			if probe >= 0 && install < 0 {
				audit = i
			}
		}
	}
	if !(lastRaw < scan && scan < probe && probe < audit && audit < install) {
		t.Fatal("incorrect epoch/probe order", lastRaw, scan, probe, audit, install)
	}
	d, _ := b.Store.Device(m.id)
	var row BackupMap
	if e = ReadSealed(filepath.Join(d, "nand-map.json"), &row); e != nil || !row.Verified() {
		t.Fatal("no verified backup", e)
	}
	var receipt Receipt
	if e = ReadSealed(filepath.Join(d, "probe.json"), &receipt); e != nil || !receipt.Audited || !receipt.Remount {
		t.Fatal("no audit", e)
	}
	if out.Stages["probe-audit"].Status != "passed" {
		t.Fatal("no audit evidence")
	}
}
func TestActualMappingMismatchStopsSimpleBeforeWrite(t *testing.T) {
	b, m := modelBackend(t, "simple")
	m.corrupt = true
	out, e := b.Execute("root", false)
	if e == nil || !strings.Contains(e.Error(), "не совпало") {
		t.Fatal("mapping mismatch accepted", e)
	}
	if out.InstallationCompleted {
		t.Fatal("false install")
	}
	for _, op := range m.events {
		if op == "probe" || op == "install" {
			t.Fatal("wrote after mismatch")
		}
	}
	d, _ := b.Store.Device(m.id)
	if Exists(filepath.Join(d, "nand-map.json")) {
		t.Fatal("bad backup verified")
	}
}
func TestExternalStockRestoreArchivesStaleHostInstall(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, e := b.Execute("root", false); e != nil {
		t.Fatal(e)
	}
	m.installed = false
	m.probe = ""
	out, e := b.Execute("root", false)
	if e != nil {
		t.Fatal("stale host active blocked stock", e)
	}
	if !out.InstallationCompleted || !Exists(filepath.Join(out.Run, "superseded-installed.json")) {
		t.Fatal("stale receipt not archived")
	}
}
func TestLiveInstalledStateBlocksRootWithoutHostReceipt(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, e := b.Execute("root", false); e != nil {
		t.Fatal(e)
	}
	d, _ := b.Store.Device(m.id)
	_ = os.Remove(filepath.Join(d, "installed.json"))
	_, e := b.Execute("root", false)
	if e == nil || !strings.Contains(e.Error(), "на устройстве уже установлен") {
		t.Fatal("relied on host only", e)
	}
}
func TestCacheMetadataChangeStopsBeforeWrite(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, e := b.Execute("root", false); e != nil {
		t.Fatal(e)
	}
	m.badChanged = true
	before := len(m.events)
	_, e := b.Execute("update", false)
	if e == nil {
		t.Fatal("changed bad blocks accepted")
	}
	for _, op := range m.events[before:] {
		if op == "refresh" {
			t.Fatal("write after metadata mismatch")
		}
	}
}
func TestUpdateAndIndependentRollbackPreserveCredentials(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, e := b.Execute("root", false); e != nil {
		t.Fatal(e)
	}
	before := len(m.events)
	out, e := b.Execute("update", false)
	if e != nil || !out.InstallationCompleted {
		t.Fatal(e)
	}
	for _, op := range m.events[before:] {
		if op == "raw" || op == "scan" {
			t.Fatal("full scan on update")
		}
	}
	d, _ := b.Store.Device(m.id)
	_ = os.Remove(filepath.Join(d, "installed.json"))
	_ = os.RemoveAll(filepath.Join(d, "credentials"))
	out, e = b.Execute("rollback", false)
	if e != nil || !out.StorageClean || m.installed {
		t.Fatal("independent rollback", e)
	}
}

func TestPackageVersionIsPropagatedInsteadOfHostVersion(t *testing.T) {
	b, m := modelBackend(t, "fast")
	out, err := b.Execute("root", false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != "9.8.7-fixture" || out.Version == Version {
		t.Fatal("lost actual package version", out.Version)
	}
	d, _ := b.Store.Device(m.id)
	var installed Installed
	if err := ReadSealed(filepath.Join(d, "installed.json"), &installed); err != nil || installed.Version != out.Version {
		t.Fatal("receipt version mismatch", err)
	}
}
func TestFastWithCachedFullBackupStillRecordsSkips(t *testing.T) {
	b, m := modelBackend(t, "simple")
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	b.Policy, _ = NewPolicy("fast", nil)
	m.events = nil
	out, err := b.Execute("update", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"backup", "full-scan", "ecc-compare", "mapping-compare", "data-compare", "probe", "probe-audit"} {
		if out.Stages[stage].Status != "skipped" {
			t.Fatal("skip mislabeled", stage, out.Stages[stage])
		}
	}
	for _, op := range m.events {
		if op == "raw" || op == "scan" || op == "read-data" || op == "probe" {
			t.Fatal("fast performed skipped operation", op)
		}
	}
}
func TestExpertCanKeepFullScanWithoutBackup(t *testing.T) {
	b, m := modelBackend(t, "expert")
	b.Policy, _ = NewPolicy("expert", []string{"backup"})
	out, err := b.Execute("root", false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stages["full-scan"].Status != "passed" {
		t.Fatal("requested scan ignored")
	}
	for _, op := range m.events {
		if op == "raw" {
			t.Fatal("unrequested backup")
		}
	}
}

func bNativeKey(r Resources, path string) ([]byte, error) {
	return r.Native("dropbearmulti", []string{"dropbearkey", "-t", "ed25519", "-f", path}, nil)
}
func modelIndex(m *Manifest) []byte {
	var out strings.Builder
	for _, n := range sortedKeys(m.Files) {
		r := m.Files[n]
		fmt.Fprintf(&out, "%04o %s %s\n", r.Mode, r.SHA, n)
	}
	return []byte(out.String())
}

func (m *model) RAMAvailable() bool { return m.restarted && m.restartDirty }
