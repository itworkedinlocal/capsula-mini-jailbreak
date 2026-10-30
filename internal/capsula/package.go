package capsula

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var lowerNames = []string{"/etc/passwd", "/etc/shadow", "/etc/profile", "/etc/init.d/S89usbgadget.sh"}
var coreNames = []string{"etc/shadow", "etc/profile", "etc/capsula-root/hostkey", "etc/init.d/S89usbgadget.sh", "usr/lib/capsula-root/service", "usr/lib/capsula-root/dropbearmulti", "usr/lib/capsula-root/supervisor", "usr/lib/capsula-root/busybox", "usr/lib/capsula-root/profile", "usr/lib/capsula-root/sftp-server"}

type FileRecord struct {
	Bytes int64  `json:"bytes"`
	SHA   string `json:"sha256"`
	Mode  int64  `json:"mode"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
}
type Toolkit struct {
	Architecture string                `json:"architecture"`
	Complete     bool                  `json:"complete"`
	Static       bool                  `json:"static_musl"`
	Files        map[string]FileRecord `json:"files"`
	Applets      []string              `json:"applets"`
	Versions     map[string]string     `json:"versions"`
}
type Manifest struct {
	Version         string                `json:"version,omitempty"`
	Schema          int                   `json:"schema_version"`
	Architecture    string                `json:"architecture"`
	Fixture         bool                  `json:"fixture_only"`
	Identity        string                `json:"device_identity,omitempty"`
	Pubkey          bool                  `json:"client_public_key_authentication"`
	Lower           map[string]string     `json:"lower_sha256"`
	Files           map[string]FileRecord `json:"files"`
	ArchiveSHA      string                `json:"archive_sha256"`
	Kernels         []string              `json:"stock_kernel_releases"`
	ToolkitVersions map[string]string     `json:"toolkit_versions,omitempty"`
	Server          string                `json:"server"`
	Authentication  string                `json:"authentication"`
	SFTP            bool                  `json:"sftp"`
	Port            int                   `json:"port"`
}

func SafePackagePath(p string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_./+\-]+$`).MatchString(p) || strings.Contains(p, "..") || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("небезопасный путь пакета %q", p)
	}
	for _, n := range append(append([]string{}, coreNames...), "etc/init.d/S95telemetry.sh") {
		if n == p {
			return nil
		}
	}
	if strings.HasPrefix(p, "usr/lib/capsula-root/") {
		return nil
	}
	return fmt.Errorf("путь вне пространства пакета %q", p)
}

// Reject duplicate keys before decoding security-relevant JSON into structs.
func UniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return fmt.Errorf("повторный/неверный ключ JSON %v", key)
					}
					seen[s] = true
					if e = value(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = value(); e != nil {
						return e
					}
				}
			default:
				return fmt.Errorf("неожиданный JSON delimiter")
			}
			end, e := d.Token()
			if e != nil {
				return e
			}
			if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
				return fmt.Errorf("повреждён JSON")
			}
		}
		return nil
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("лишние данные JSON")
	}
	return nil
}
func ValidatePackage(folder, id string, hashes bool) (*Manifest, error) {
	var m Manifest
	if e := readJSON(filepath.Join(folder, "manifest.json"), &m); e != nil {
		return nil, e
	}
	if m.Schema != 2 || m.Architecture != "aarch64" || m.Fixture || m.Pubkey || (id != "" && m.Identity != id) {
		return nil, fmt.Errorf("пакет не соответствует архитектуре/устройству/password-only")
	}
	if len(m.Lower) != len(lowerNames) {
		return nil, fmt.Errorf("неверный lower inventory")
	}
	for _, n := range lowerNames {
		if !digestRE.MatchString(m.Lower[n]) {
			return nil, fmt.Errorf("неверный lower hash")
		}
	}
	for _, n := range coreNames {
		if _, ok := m.Files[n]; !ok {
			return nil, fmt.Errorf("неполный пакет: %s", n)
		}
	}
	var total int64
	for name, row := range m.Files {
		if e := SafePackagePath(name); e != nil {
			return nil, e
		}
		if !digestRE.MatchString(row.SHA) || (row.Mode != 0600 && row.Mode != 0644 && row.Mode != 0755) || row.UID != 0 || row.GID != 0 || row.Bytes < 0 || row.Bytes > 32<<20 {
			return nil, fmt.Errorf("неверные metadata %s", name)
		}
		total += row.Bytes
		for p := path.Dir(name); p != "."; p = path.Dir(p) {
			if _, ok := m.Files[p]; ok {
				return nil, fmt.Errorf("файл используется как каталог")
			}
		}
	}
	if total > 32<<20 {
		return nil, fmt.Errorf("пакет не помещается в RAM")
	}
	for _, name := range []string{"manifest.json", "overlay-files.tar", "files.sha256", "files.tsv", "lower.sha256", "payload-bytes"} {
		i, e := os.Lstat(filepath.Join(folder, name))
		if e != nil || !i.Mode().IsRegular() {
			return nil, fmt.Errorf("не найден обычный файл пакета %s", name)
		}
	}
	if !digestRE.MatchString(m.ArchiveSHA) {
		return nil, fmt.Errorf("неверный hash архива")
	}
	if hashes {
		h, e := FileSHA(filepath.Join(folder, "overlay-files.tar"))
		if e != nil {
			return nil, e
		}
		if h != m.ArchiveSHA {
			return nil, fmt.Errorf("hash архива не совпадает")
		}
	}
	for _, index := range []string{"files.tsv", "files.sha256", "lower.sha256"} {
		b, e := os.ReadFile(filepath.Join(folder, index))
		if e != nil {
			return nil, e
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			fields := strings.Fields(line)
			want := 2
			if index == "files.tsv" {
				want = 3
			}
			if len(fields) != want {
				return nil, fmt.Errorf("неверный индекс %s", index)
			}
			name := fields[len(fields)-1]
			if seen[name] {
				return nil, fmt.Errorf("дубликат в индексе")
			}
			seen[name] = true
			if index == "lower.sha256" {
				if m.Lower[strings.TrimPrefix(name, "/stock")] != fields[0] {
					return nil, fmt.Errorf("lower индекс не совпадает")
				}
			} else {
				row, ok := m.Files[name]
				if !ok {
					return nil, fmt.Errorf("посторонний файл в индексе")
				}
				h := fields[0]
				if index == "files.tsv" {
					mode, e := strconv.ParseInt(fields[0], 8, 32)
					if e != nil || mode != row.Mode {
						return nil, fmt.Errorf("неверные права в индексе")
					}
					h = fields[1]
				}
				if h != row.SHA {
					return nil, fmt.Errorf("индекс не соответствует manifest")
				}
			}
		}
		count := len(m.Files)
		if index == "lower.sha256" {
			count = len(m.Lower)
		}
		if len(seen) != count {
			return nil, fmt.Errorf("неполный индекс %s", index)
		}
	}
	b, e := os.ReadFile(filepath.Join(folder, "payload-bytes"))
	if e != nil || string(b) != fmt.Sprint(total)+"\n" {
		return nil, fmt.Errorf("неверный payload-bytes")
	}
	f, e := os.Open(filepath.Join(folder, "overlay-files.tar"))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	tr := tar.NewReader(f)
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		row, ok := m.Files[h.Name]
		if e := SafePackagePath(h.Name); e != nil {
			return nil, e
		}
		if !ok || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Linkname != "" || len(h.PAXRecords) != 0 || h.Size != row.Bytes || h.Mode != row.Mode || h.Uid != 0 || h.Gid != 0 {
			return nil, fmt.Errorf("неверный/дублированный tar member %s", h.Name)
		}
		seen[h.Name] = true
		data, e := io.ReadAll(io.LimitReader(tr, row.Bytes+1))
		if e != nil || int64(len(data)) != row.Bytes {
			return nil, fmt.Errorf("укороченный tar member")
		}
		if hashes && SHA(data) != row.SHA {
			return nil, fmt.Errorf("не совпало содержимое %s", h.Name)
		}
	}
	if len(seen) != len(m.Files) {
		return nil, fmt.Errorf("неполный tar")
	}
	return &m, nil
}

type StockBundle struct {
	Files             map[string][]byte `json:"files"`
	Kernels           []string          `json:"kernels"`
	Installed         bool              `json:"installed"`
	DeviceState       string            `json:"device_state,omitempty"`
	InstalledManifest *Manifest         `json:"installed_manifest,omitempty"`
	Probe             []byte            `json:"probe,omitempty"`
	ProbeProof        []byte            `json:"probe_proof,omitempty"`
	InstalledIndex    []byte            `json:"installed_index,omitempty"`
	HostKey           []byte            `json:"host_key,omitempty"`
	Shadow            []byte            `json:"shadow,omitempty"`
}

func ParseDeviceExport(body string) (StockBundle, error) {
	b := StockBundle{Files: map[string][]byte{}, Kernels: []string{}}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != "DEVICE_CLEAN" {
		return b, fmt.Errorf("нет clean detach при чтении stock/device")
	}
	stateCount := 0
	seen := map[string]bool{}
	for _, line := range lines[:len(lines)-1] {
		if line == "DEVICE_INSTALLED" || line == "DEVICE_STOCK" {
			stateCount++
			b.Installed = line == "DEVICE_INSTALLED"
			continue
		}
		if strings.HasPrefix(line, "KERNEL ") {
			release := strings.TrimPrefix(line, "KERNEL ")
			if !regexp.MustCompile(`^[a-zA-Z0-9_.+\-]+$`).MatchString(release) {
				return b, fmt.Errorf("неверное имя ядра")
			}
			b.Kernels = append(b.Kernels, release)
			continue
		}
		fields := strings.SplitN(line, " ", 4)
		if len(fields) != 4 || fields[0] != "FILE" || seen[fields[1]] || !digestRE.MatchString(fields[2]) {
			return b, fmt.Errorf("повреждён export")
		}
		name := fields[1]
		seen[name] = true
		data, e := base64.StdEncoding.DecodeString(fields[3])
		if e != nil || len(data) > 1<<20 || SHA(data) != fields[2] {
			return b, fmt.Errorf("export hash/size: %s", name)
		}
		if strings.HasPrefix(name, "/stock/") {
			rel := strings.TrimPrefix(name, "/stock")
			found := false
			for _, n := range lowerNames {
				if rel == n {
					found = true
				}
			}
			if !found || len(data) > 262144 {
				return b, fmt.Errorf("лишний stock file")
			}
			b.Files[rel] = data
		} else {
			switch name {

			case "/data/.capsula-root-state/manifest.json":
				var m Manifest
				if e := UniqueJSON(data); e != nil {
					return b, e
				}
				if e = json.Unmarshal(data, &m); e != nil {
					return b, e
				}
				b.InstalledManifest = &m
			case "/data/.capsula-root-state/state":
				b.DeviceState = strings.TrimSpace(string(data))
			case "/data/.capsula-root-state/files.tsv":
				b.InstalledIndex = data
			case "/data/.capsula-root-state/probe.sha256":
				if len(data) != 65 || !digestRE.Match(data[:64]) || data[64] != '\n' {
					return b, fmt.Errorf("повреждён proof пробной записи")
				}
				b.ProbeProof = data
			case "/data/overlay/upper/etc/capsula-root/hostkey":
				if len(data) == 0 || len(data) > 16384 {
					return b, fmt.Errorf("неверный размер host key")
				}
				b.HostKey = data
			case "/data/overlay/upper/etc/shadow":
				if len(data) > 262144 {
					return b, fmt.Errorf("неверный размер shadow")
				}
				b.Shadow = data
			case "/data/.capsula-root-probe":
				if len(data) != 65 || !digestRE.Match(data[:64]) || data[64] != '\n' {
					return b, fmt.Errorf("чужой/неверный probe")
				}
				b.Probe = data
			default:
				return b, fmt.Errorf("лишний экспортируемый путь")
			}
		}
	}
	if stateCount != 1 || len(b.Files) != 4 {
		return b, fmt.Errorf("неполный stock/device export")
	}
	if b.Installed && (b.DeviceState == "" || (b.InstalledManifest == nil && b.DeviceState != "preparing")) {
		return b, fmt.Errorf("неполное состояние установленного пакета")
	}
	return b, nil
}

var generatedPasswordHashRE = regexp.MustCompile(`^\$6\$rounds=100000\$[0-9a-f]{16}\$[./0-9A-Za-z]{86}(?:\r?\n)?$`)

func normalizeGeneratedPasswordHash(hashed []byte) ([]byte, error) {
	// The C helper uses puts: Windows text-mode stdout emits CRLF, Linux LF.
	// Validate the whole output before normalizing one optional line ending.
	if !generatedPasswordHashRE.Match(hashed) {
		return nil, fmt.Errorf("неверный hash пароля")
	}
	return append(bytes.TrimRight(hashed, "\r\n"), '\n'), nil
}

func BuildPackage(r Resources, folder, device, id string, stock StockBundle, password func() ([]byte, error), verifyHashes bool) (*Manifest, error) {
	if e := PrivateDir(folder); e != nil {
		return nil, e
	}
	creds := filepath.Join(device, "credentials")
	if e := PrivateDir(creds); e != nil {
		return nil, e
	}
	hashPath := filepath.Join(creds, "root-password.hash")
	if !Exists(hashPath) {
		pw, e := password()
		if e != nil {
			return nil, e
		}
		defer clear(pw)
		if e = ValidatePassword(pw); e != nil {
			return nil, e
		}
		hashed, e := r.Native("password-hash", nil, pw)
		if e != nil {
			return nil, e
		}
		hashed, e = normalizeGeneratedPasswordHash(hashed)
		if e != nil {
			return nil, e
		}
		if e = writePrivateExclusive(hashPath, hashed); e != nil {
			return nil, e
		}
	}
	hf, e := openPrivate(hashPath)
	if e != nil {
		return nil, e
	}
	info, e := hf.Stat()
	if e != nil || !info.Mode().IsRegular() || owned(info) != nil || !privatePermissions(info) {
		hf.Close()
		return nil, fmt.Errorf("неверные права сохранённого password hash")
	}
	hashed, e := io.ReadAll(io.LimitReader(hf, 1024))
	hf.Close()
	if e != nil || !passwordHashRE.Match(bytes.TrimSpace(hashed)) {
		return nil, fmt.Errorf("повреждён сохранённый password hash")
	}
	hashed = bytes.TrimSpace(hashed)
	keyPath := filepath.Join(creds, "hostkey")
	if info, e := os.Lstat(keyPath); e == nil && (!info.Mode().IsRegular() || owned(info) != nil || !privatePermissions(info)) {
		return nil, fmt.Errorf("неверный тип или права host key")
	}
	if !Exists(keyPath) {
		if _, e = r.Native("dropbearmulti", []string{"dropbearkey", "-t", "ed25519", "-f", keyPath}, nil); e != nil {
			return nil, e
		}
		if e = os.Chmod(keyPath, 0600); e != nil {
			return nil, e
		}
	}
	key, e := os.ReadFile(keyPath)
	if e != nil {
		return nil, e
	}
	public, e := r.Native("dropbearmulti", []string{"dropbearkey", "-y", "-f", keyPath}, nil)
	if e != nil {
		return nil, e
	}
	publicKey := ""
	for _, line := range strings.Split(string(public), "\n") {
		if strings.HasPrefix(line, "ssh-ed25519 ") {
			publicKey = line
		}
	}
	if publicKey == "" {
		return nil, fmt.Errorf("не получен public host key")
	}
	files := map[string][]byte{}
	m := &Manifest{Version: Version, Schema: 2, Architecture: "aarch64", Identity: id, Lower: map[string]string{}, Files: map[string]FileRecord{}, Kernels: stock.Kernels, Server: "Dropbear 2026.94", Authentication: "root password, SHA512-crypt", SFTP: true, Port: 22}
	for _, n := range lowerNames {
		body, ok := stock.Files[n]
		if !ok {
			return nil, fmt.Errorf("нет stock file %s", n)
		}
		m.Lower[n] = SHA(body)
	}
	shadow := stock.Files["/etc/shadow"]
	lines := bytes.SplitAfter(shadow, []byte("\n"))
	count := 0
	for i, line := range lines {
		fields := bytes.Split(line, []byte(":"))
		if len(fields) > 1 && string(fields[0]) == "root" {
			fields[1] = hashed
			lines[i] = bytes.Join(fields, []byte(":"))
			count++
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("stock root shadow отсутствует/дублируется")
	}
	files["etc/shadow"] = bytes.Join(lines, nil)
	profile := stock.Files["/etc/profile"]
	if bytes.Count(profile, []byte("`id -u`")) != 1 {
		return nil, fmt.Errorf("неподдерживаемый stock профиль входа")
	}
	files["etc/profile"] = append(bytes.Replace(profile, []byte("`id -u`"), []byte("$(/usr/lib/capsula-root/supervisor uid)"), 1), []byte("\n. /usr/lib/capsula-root/profile\n")...)
	files["etc/capsula-root/hostkey"] = key
	for dest, src := range map[string]string{"usr/lib/capsula-root/dropbearmulti": "bin/aarch64/dropbearmulti", "usr/lib/capsula-root/supervisor": "bin/aarch64/supervisor", "usr/lib/capsula-root/service": "payload/service", "etc/init.d/S89usbgadget.sh": "payload/S89usbgadget.sh", "usr/lib/capsula-root/profile": "payload/profile", "usr/lib/capsula-root/bin/capsula": "payload/capsula", "usr/lib/capsula-root/entware": "payload/entware", "etc/init.d/S95telemetry.sh": "payload/S95telemetry.sh", "usr/lib/capsula-root/bin/opkg": "payload/entware-opkg"} {
		body, e := os.ReadFile(r.Stock(src))
		if e != nil {
			return nil, e
		}
		files[dest] = body
	}
	logo, e := os.ReadFile(r.Logo)
	if e != nil {
		return nil, e
	}
	files["usr/lib/capsula-root/fastfetch.jsonc"] = logo
	var tk Toolkit
	if e = readJSON(r.Stock("toolkit/aarch64/manifest.json"), &tk); e != nil {
		return nil, e
	}
	m.ToolkitVersions = tk.Versions
	for name, row := range tk.Files {
		if e = r.Pinned(r.Stock("toolkit/aarch64/"+name), row.SHA); e != nil {
			return nil, e
		}
		dest := "usr/lib/capsula-root/" + name
		if name == "nano" || name == "htop" || name == "fastfetch" || name == "curl" {
			dest = "usr/lib/capsula-root/bin/" + name
		}
		data, e := os.ReadFile(r.Stock("toolkit/aarch64/" + name))
		if e != nil {
			return nil, e
		}
		files[dest] = data
		m.Files[dest] = row
	}
	if len(tk.Applets) == 0 {
		return nil, fmt.Errorf("нет applet inventory")
	}
	for _, applet := range tk.Applets {
		if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(applet) {
			return nil, fmt.Errorf("неверный applet")
		}
		files["usr/lib/capsula-root/bin/"+applet] = []byte("#!/bin/sh\nexec /usr/lib/capsula-root/busybox " + applet + " \"$@\"\n")
	}
	var entware struct {
		Files map[string]struct {
			Source string `json:"source"`
			SHA    string `json:"sha256"`
			Mode   int64  `json:"mode"`
		} `json:"files"`
	}
	if e = readJSON(r.Stock("entware-sources.json"), &entware); e != nil {
		return nil, e
	}
	for name, row := range entware.Files {
		dest := "usr/lib/capsula-root/entware-bootstrap/" + name
		if e = SafePackagePath(dest); e != nil {
			return nil, e
		}
		source, e := SafeJoin(r.Stock("sources"), row.Source)
		if e != nil {
			return nil, e
		}
		if e = r.Pinned(source, row.SHA); e != nil {
			return nil, e
		}
		data, e := os.ReadFile(source)
		if e != nil {
			return nil, e
		}
		files[dest] = data
		m.Files[dest] = FileRecord{Mode: row.Mode}
	}
	for name, src := range map[string]string{"bin/wget": "payload/entware-wget", "opkg-wrapper": "payload/entware-opkg"} {
		data, e := os.ReadFile(r.Stock(src))
		if e != nil {
			return nil, e
		}
		files["usr/lib/capsula-root/entware-bootstrap/"+name] = data
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	var indexes, hashes, lower bytes.Buffer
	var total int64
	for _, name := range sortedKeys(files) {
		if e = SafePackagePath(name); e != nil {
			return nil, e
		}
		body := files[name]
		mode := int64(0755)
		if row, ok := m.Files[name]; ok {
			mode = row.Mode
		} else if name == "etc/shadow" || name == "etc/capsula-root/hostkey" {
			mode = 0600
		} else if name == "etc/profile" || (name == "etc/init.d/S89usbgadget.sh" || name == "etc/init.d/S95telemetry.sh") || name == "usr/lib/capsula-root/profile" || strings.HasSuffix(name, ".jsonc") {
			mode = 0644
		}
		row := FileRecord{int64(len(body)), SHA(body), mode, 0, 0}
		m.Files[name] = row
		total += row.Bytes
		if e = tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: row.Bytes, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			return nil, e
		}
		if _, e = tw.Write(body); e != nil {
			return nil, e
		}
		fmt.Fprintf(&indexes, "%04o %s %s\n", mode, row.SHA, name)
		fmt.Fprintf(&hashes, "%s  %s\n", row.SHA, name)
	}
	if e = tw.Close(); e != nil {
		return nil, e
	}
	m.ArchiveSHA = SHA(archive.Bytes())
	for _, n := range sortedKeys(m.Lower) {
		fmt.Fprintf(&lower, "%s  /stock%s\n", m.Lower[n], n)
	}
	for name, body := range map[string][]byte{"overlay-files.tar": archive.Bytes(), "files.tsv": indexes.Bytes(), "files.sha256": hashes.Bytes(), "lower.sha256": lower.Bytes(), "payload-bytes": []byte(fmt.Sprint(total) + "\n"), "server-hostkey.pub": []byte(publicKey + "\n")} {
		if e = writePrivateExclusive(filepath.Join(folder, name), body); e != nil {
			return nil, e
		}
	}
	if e = AtomicJSON(filepath.Join(folder, "manifest.json"), m); e != nil {
		return nil, e
	}
	return ValidatePackage(folder, id, verifyHashes)
}
func writePrivateExclusive(path string, b []byte) error {
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
