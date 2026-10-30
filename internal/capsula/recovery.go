package capsula

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var passwordHashRE = regexp.MustCompile(`^\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$`)

func rootPasswordHash(shadow []byte) ([]byte, error) {
	var hash []byte
	count := 0
	for _, line := range bytes.Split(shadow, []byte("\n")) {
		f := bytes.Split(line, []byte(":"))
		if len(f) > 0 && string(f[0]) == "root" {
			count++
			if len(f) != 9 || !passwordHashRE.Match(f[1]) {
				return nil, fmt.Errorf("на колонке неподдерживаемый или заблокированный пароль root")
			}
			hash = append([]byte(nil), f[1]...)
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("на колонке отсутствует или повторяется root в shadow")
	}
	return hash, nil
}

func publicHostKey(r Resources, path string) (string, error) {
	data, err := r.Native("dropbearmulti", []string{"dropbearkey", "-y", "-f", path}, nil)
	if err != nil {
		return "", fmt.Errorf("host key колонки не читается: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "ssh-ed25519" {
			return strings.Join(f[:2], " "), nil
		}
	}
	return "", fmt.Errorf("host key колонки не является Ed25519")
}

func (c *connection) recoverCredentials() error {
	body, err := c.console("credentials")
	if err != nil {
		return err
	}
	live, err := ParseDeviceExport(body)
	if err != nil {
		return err
	}
	if !live.Installed || live.DeviceState != "active" || live.InstalledManifest == nil || live.InstalledManifest.Schema != 2 || live.InstalledManifest.Architecture != "aarch64" || live.InstalledManifest.Fixture || live.InstalledManifest.Identity != c.id || live.InstalledManifest.ArchiveSHA != c.stock.InstalledManifest.ArchiveSHA {
		return fmt.Errorf("установка изменилась во время чтения credentials")
	}
	if len(live.HostKey) == 0 || len(live.InstalledIndex) == 0 {
		return fmt.Errorf("неполный экспорт credentials установленного пакета")
	}
	if err = validateInstalledIndex(live); err != nil {
		return err
	}
	hash, err := rootPasswordHash(live.Shadow)
	if err != nil {
		return err
	}
	defer clear(hash)
	keyPath := filepath.Join(c.run, "recovered-hostkey")
	if err = writePrivateExclusive(keyPath, live.HostKey); err != nil {
		return err
	}
	pub, err := publicHostKey(c.b.Resources, keyPath)
	if err != nil {
		return err
	}
	path := filepath.Join(c.device, "installed.json")
	if Exists(path) {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || !privatePermissions(info) || owned(info) != nil {
			return fmt.Errorf("небезопасная локальная квитанция установки")
		}
		var old Installed
		if e = ReadSealed(path, &old); e == nil {
			if old.Identity != c.id {
				return fmt.Errorf("локальная квитанция принадлежит другой колонке")
			}
			f := strings.Fields(old.PublicKey)
			if old.State == "active" && (len(f) < 2 || strings.Join(f[:2], " ") != pub) {
				return fmt.Errorf("SSH host key колонки отличается от сохранённого; автоматическая замена pin запрещена")
			}
		}
	}
	// Validate all inputs before superseding any host history. The physical USB
	// identity and live kernel view are the source for a new host enrollment.
	creds := filepath.Join(c.device, "credentials")
	if Exists(creds) {
		if err = PrivateDir(creds); err != nil {
			return err
		}
		if err = c.archiveState("credentials", "credentials получены с колонки через RO RAM"); err != nil {
			return err
		}
	}
	if err = PrivateDir(creds); err != nil {
		return err
	}
	if err = writePrivateExclusive(filepath.Join(creds, "hostkey"), live.HostKey); err != nil {
		return err
	}
	if err = writePrivateExclusive(filepath.Join(creds, "root-password.hash"), hash); err != nil {
		return err
	}
	if err = c.archiveState("installed.json", "актуальное состояние получено с колонки перед update"); err != nil {
		return err
	}
	c.b.Notify("Состояние установки прочитано с Капсулы. Пароль root и SSH host key сохраняются.")
	return c.phase("credentials-recovered", nil)
}

func validateInstalledIndex(b StockBundle) error {
	m := b.InstalledManifest
	if m == nil || m.Schema != 2 || m.Pubkey {
		return fmt.Errorf("неподдерживаемый установленный манифест")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b.InstalledIndex)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			return fmt.Errorf("повреждён установленный индекс")
		}
		if err := SafePackagePath(f[2]); err != nil {
			return err
		}
		mode, err := strconv.ParseInt(f[0], 8, 64)
		r, ok := m.Files[f[2]]
		if err != nil || !ok || seen[f[2]] || (mode != 0600 && mode != 0644 && mode != 0755) || !digestRE.MatchString(f[1]) || r.SHA != f[1] || r.Mode != mode || r.Bytes < 0 || r.Bytes > 32<<20 || r.UID != 0 || r.GID != 0 {
			return fmt.Errorf("установленный индекс не соответствует манифесту")
		}
		seen[f[2]] = true
	}
	if len(seen) != len(m.Files) {
		return fmt.Errorf("неполный установленный индекс")
	}
	for _, n := range coreNames {
		if !seen[n] {
			return fmt.Errorf("неполный установленный пакет: %s", n)
		}
	}
	return nil
}
