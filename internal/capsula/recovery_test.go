package capsula

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateRecoversMissingHostHistory(t *testing.T) {
	for _, missing := range []string{"installed.json", "credentials", "package", "everything"} {
		t.Run(missing, func(t *testing.T) {
			b, m := modelBackend(t, "fast")
			out, err := b.Execute("root", false)
			if err != nil {
				t.Fatal(err)
			}
			d, _ := b.Store.Device(m.id)
			key, hash := string(m.key), string(m.hash)
			switch missing {
			case "everything":
				b.Store, err = NewStore(filepath.Join(t.TempDir(), "devices"))
			case "package":
				err = os.RemoveAll(filepath.Join(out.Run, "package"))
			default:
				err = os.RemoveAll(filepath.Join(d, missing))
			}
			if err != nil {
				t.Fatal(err)
			}
			b.Password = func() ([]byte, error) { t.Fatal("requested replacement password"); return nil, nil }
			out, err = b.Execute("update", false)
			if err != nil {
				t.Fatal(err)
			}
			if !out.InstallationCompleted || string(m.key) != key || string(m.hash) != hash {
				t.Fatal("credentials lost")
			}
			d, _ = b.Store.Device(m.id)
			var installed Installed
			if err = ReadSealed(filepath.Join(d, "installed.json"), &installed); err != nil {
				t.Fatal(err)
			}
			if _, err = ValidatePackage(filepath.Join(d, installed.Package), m.id, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpdateRejectsChangedPinBeforeProbeOrWrite(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	d, _ := b.Store.Device(m.id)
	var installed Installed
	if err := ReadSealed(filepath.Join(d, "installed.json"), &installed); err != nil {
		t.Fatal(err)
	}
	installed.PublicKey = "ssh-ed25519 foreign-key"
	if err := SaveSealed(filepath.Join(d, "installed.json"), installed); err != nil {
		t.Fatal(err)
	}
	before := len(m.events)
	_, err := b.Execute("update", false)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatal("pin mismatch accepted", err)
	}
	for _, event := range m.events[before:] {
		if event == "refresh" || event == "probe" {
			t.Fatal("wrote after pin mismatch")
		}
	}
}

func TestIndependentRollbackDoesNotReadCredentials(t *testing.T) {
	b, m := modelBackend(t, "fast")
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	m.credentialError = true
	b.Store, _ = NewStore(filepath.Join(t.TempDir(), "devices"))
	before := len(m.events)
	if _, err := b.Execute("rollback", false); err != nil {
		t.Fatal(err)
	}
	for _, event := range m.events[before:] {
		if event == "credentials" {
			t.Fatal("rollback needed credentials")
		}
	}
}

func TestRootHashRejectsLockedDuplicatedAndInvalidEntries(t *testing.T) {
	hash := "$6$rounds=100000$0123456789abcdef$" + strings.Repeat("A", 86)
	line := "root:" + hash + ":0:0:99999:7:::\n"
	for _, body := range []string{"", strings.Replace(line, hash, "!"+hash, 1), line + line, strings.Replace(line, hash, "$6$bad", 1)} {
		if _, err := rootPasswordHash([]byte(body)); err == nil {
			t.Fatal("accepted bad shadow")
		}
	}
	if got, err := rootPasswordHash([]byte(line)); err != nil || string(got) != hash {
		t.Fatal(err)
	}
}

func TestSimpleUpdateReenrollsProbeFromDevice(t *testing.T) {
	b, m := modelBackend(t, "simple")
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	token := m.probe
	b.Store, _ = NewStore(filepath.Join(t.TempDir(), "devices"))
	before := len(m.events)
	out, err := b.Execute("update", false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.InstallationCompleted || m.probe != token {
		t.Fatal("existing marker changed")
	}
	checked := false
	for _, event := range m.events[before:] {
		if event == "probe-check" {
			checked = true
		}
		if event == "probe" {
			t.Fatal("replaced existing marker")
		}
	}
	if !checked {
		t.Fatal("did not recheck live marker")
	}
}

func TestInvalidLiveCredentialsStopUpdateBeforeWrite(t *testing.T) {
	for _, kind := range []string{"foreign-identity", "invalid-key", "locked-password", "incomplete-export"} {
		t.Run(kind, func(t *testing.T) {
			b, m := modelBackend(t, "fast")
			if _, err := b.Execute("root", false); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign-identity":
				m.manifest.Identity = strings.Repeat("f", 64)
			case "invalid-key":
				m.key = []byte("not a Dropbear key")
			case "locked-password":
				m.hash = []byte("!locked")
			case "incomplete-export":
				m.credentialError = true
			}
			before := len(m.events)
			if _, err := b.Execute("update", false); err == nil {
				t.Fatal("bad live credentials accepted")
			}
			for _, event := range m.events[before:] {
				if event == "refresh" || event == "probe" || event == "probe-check" {
					t.Fatal("write after invalid export")
				}
			}
		})
	}
}

func TestInstalledIndexRejectsMissingDuplicateAndForeignPaths(t *testing.T) {
	m, err := fixturePackage(t, strings.Repeat("a", 64), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	valid := modelIndex(m)
	for _, index := range []string{"", string(valid) + string(valid), strings.Replace(string(valid), "etc/shadow", "../../etc/shadow", 1), strings.Replace(string(valid), m.Files["etc/shadow"].SHA, strings.Repeat("f", 64), 1)} {
		if err := validateInstalledIndex(StockBundle{InstalledManifest: m, InstalledIndex: []byte(index)}); err == nil {
			t.Fatal("invalid index accepted")
		}
	}
}
