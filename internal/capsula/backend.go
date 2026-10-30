package capsula

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type BackupMap struct {
	Schema     int                        `json:"schema"`
	Profile    Profile                    `json:"profile"`
	Backup     map[string]json.RawMessage `json:"backup"`
	VerifiedAt string                     `json:"verified_at"`
}

func (m BackupMap) Verified() bool {
	var ecc, mapping bool
	_ = json.Unmarshal(m.Backup["ecc_reads_match"], &ecc)
	_ = json.Unmarshal(m.Backup["physical_mapping_verified"], &mapping)
	return m.Schema == 1 && ecc && mapping && m.Profile.Validate() == nil
}

type ProfileRecord struct {
	Schema    int     `json:"schema"`
	Profile   Profile `json:"profile"`
	Basis     string  `json:"basis"`
	UpdatedAt string  `json:"updated_at"`
}
type Installed struct {
	Version          string            `json:"version,omitempty"`
	State            string            `json:"state"`
	Identity         string            `json:"identity"`
	Package          string            `json:"package"`
	ArchiveSHA       string            `json:"archive_sha256"`
	PublicKey        string            `json:"public_key"`
	CredentialHashes map[string]string `json:"credential_hashes"`
	Run              string            `json:"run"`
	Policy           *Policy           `json:"policy,omitempty"`
}
type Receipt struct {
	Identity   string `json:"identity"`
	ProfileSHA string `json:"profile_sha256"`
	Token      string `json:"token"`
	PostSHA    string `json:"post_write_sha256"`
	Audited    bool   `json:"loader_audit_verified"`
	TokenSHA   string `json:"probe_token_sha256,omitempty"`
	Remount    bool   `json:"probe_remount_verified,omitempty"`
	Run        string `json:"run,omitempty"`
}
type ReadPair struct {
	Reads []Artifact `json:"reads"`
	Bytes int64      `json:"bytes"`
	SHA   string     `json:"sha256"`
	Match bool       `json:"ecc_reads_match"`
}
type Backend struct {
	Ctx              context.Context
	Store            *Store
	Resources        Resources
	Policy           Policy
	ExpectedIdentity string
	Wait             time.Duration
	NewTransport     func(context.Context, Resources, string) (Transport, error)
	RAMBuilder       func(Resources, string, RAMOptions) (RAMBundle, error)
	Password         func() ([]byte, error)
	Notify           func(string)
	Progress         func(ProgressEvent)
	Reconnect        func(string) error
	BeforeWrite      func(string, string, Policy) error
	PackageBuilder   func(Resources, string, string, string, StockBundle, func() ([]byte, error), bool) (*Manifest, error)
}

func (b *Backend) defaults() {
	if b.Ctx == nil {
		b.Ctx = context.Background()
	}
	if b.Wait <= 0 {
		b.Wait = 180 * time.Second
	}
	if b.NewTransport == nil {
		b.NewTransport = func(c context.Context, r Resources, p string) (Transport, error) { return NewUSB(c, r, p) }
	}
	if b.RAMBuilder == nil {
		b.RAMBuilder = BuildRAM
	}
	if b.PackageBuilder == nil {
		b.PackageBuilder = BuildPackage
	}
	if b.Notify == nil {
		b.Notify = func(s string) { fmt.Println(s) }
	}
}

type connection struct {
	b                      *Backend
	t                      Transport
	id, device, run, slot  string
	layout                 Layout
	profile                Profile
	stock                  StockBundle
	stockSlot              string
	bundle                 RAMBundle
	ramN, loaderN, reportN int
	loader                 bool
	backupVerified         bool
	out                    *Outcome
	unlock                 func()
	bootEnv                map[string]string
}

func (c *connection) phase(name string, extra map[string]any) error {
	labels := map[string]string{"identified": "Устройство определено", "building-ram": "Подготовка временной RAM-среды", "backup-complete": "Бэкап сохранён и проверен", "credentials-recovered": "Пароль и ключ восстановлены с колонки", "writing-refresh": "Обновление файлов на колонке", "writing-install": "Установка файлов на колонке", "writing-rollback": "Возврат штатных файлов", "complete": "Операция завершена"}
	if c.b.Progress != nil {
		label := labels[name]
		detail := label
		if detail == "" {
			detail = "phase=" + name
		}
		c.b.Progress(ProgressEvent{Stage: name, Detail: detail, Verbose: label == ""})
	}
	row := map[string]any{"operation": c.out.Operation, "phase": name, "identity": c.id, "policy": c.b.Policy, "updated_at": Now()}
	for k, v := range extra {
		row[k] = v
	}
	return AtomicJSON(filepath.Join(c.run, "session.json"), row)
}
func (c *connection) finish(err error) {
	if err == nil {
		for stage, result := range c.out.Stages {
			if result.Status == "pending" && (stage != "ssh" || (c.out.Operation != "root" && c.out.Operation != "update")) {
				c.out.Stages[stage] = StageResult{"not_required", "не требуется этой операцией"}
			}
		}
	}
	if err != nil {
		c.out.Error = err.Error()
		_ = c.phase("failed", map[string]any{"error": err.Error()})
	} else {
		_ = c.phase("complete", nil)
	}
	_ = AtomicJSON(filepath.Join(c.run, "result.json"), c.out)
	if c.unlock != nil {
		c.unlock()
	}
	c.t.Close()
}
func identity(t Transport) (string, error) {
	off, size := Reserved["keys"][0], Reserved["keys"][1]
	a, e := t.ReadReserved(off, size, "identity-0.bin")
	if e != nil {
		return "", e
	}
	bb, e := t.ReadReserved(off, size, "identity-1.bin")
	if e != nil {
		return "", e
	}
	if _, e = CompareECC(a, bb, size); e != nil {
		return "", e
	}
	body, e := os.ReadFile(a)
	if e != nil {
		return "", e
	}
	different := false
	for _, x := range body {
		if x != body[0] {
			different = true
			break
		}
	}
	if !different {
		return "", fmt.Errorf("keys-область не содержит устойчивой идентичности")
	}
	return SHA(append([]byte("Capsula A113X keys identity v1\x00"), body...)), nil
}
func (b *Backend) connect(operation string) (*connection, error) {
	b.defaults()
	if e := b.Policy.Validate(); e != nil {
		return nil, e
	}
	incoming := filepath.Join(filepath.Dir(b.Store.Root), "incoming")
	if e := PrivateDir(incoming); e != nil {
		return nil, e
	}
	folder, e := os.MkdirTemp(incoming, operation+"-*")
	if e != nil {
		return nil, e
	}
	fail := func(e error) {
		_ = AtomicJSON(filepath.Join(folder, "session.json"), map[string]any{"operation": operation, "phase": "failed", "error": e.Error(), "updated_at": Now()})
	}
	if e = AtomicJSON(filepath.Join(folder, "session.json"), map[string]any{"operation": operation, "phase": "connecting", "started_at": Now()}); e != nil {
		return nil, e
	}
	t, e := b.NewTransport(b.Ctx, b.Resources, folder)
	if e != nil {
		fail(e)
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			t.Close()
		}
	}()
	if preparer, supported := t.(interface{ Prepare(func(string)) error }); supported {
		if e = preparer.Prepare(b.Notify); e != nil {
			fail(e)
			return nil, e
		}
	}
	b.Notify("Отключите USB и штатный БП на 10 секунд, затем подключите только USB-кабель данных.\nДальнейшие переходы выполняются автоматически, если загрузчик поддерживается.")
	if b.Progress != nil {
		b.Progress(ProgressEvent{Stage: "waiting-usb", Detail: "Ожидание Капсулы по USB · Ctrl+C — выход"})
	}
	if e = t.Wait(b.Wait); e != nil {
		fail(e)
		return nil, e
	}
	bootEnv, tree, slot, e := t.Metadata()
	if e != nil {
		fail(e)
		return nil, e
	}
	layout, e := LayoutFromTree(tree)
	if e != nil {
		fail(e)
		return nil, e
	}
	id, e := identity(t)
	if e != nil {
		fail(e)
		return nil, e
	}
	if b.ExpectedIdentity != "" && b.ExpectedIdentity != id {
		e = fmt.Errorf("подключена другая колонка")
		fail(e)
		return nil, e
	}
	device, e := b.Store.Device(id)
	if e != nil {
		return nil, e
	}
	unlock, e := b.Store.Lock(id)
	if e != nil {
		return nil, e
	}
	dest, e := b.Store.Run(id, operation)
	if e != nil {
		unlock()
		return nil, e
	}
	if e = os.Remove(dest); e == nil {
		e = os.Rename(folder, dest)
	}
	if e != nil {
		unlock()
		return nil, e
	}
	folder = dest
	if e = t.SetFolder(folder); e != nil {
		unlock()
		return nil, e
	}
	out := NewOutcome(operation, b.Policy)
	out.Identity = id
	out.Run = folder
	c := &connection{b: b, t: t, id: id, device: device, run: folder, slot: slot, layout: layout, loader: true, out: out, unlock: unlock, bootEnv: bootEnv}
	if e = c.phase("identified", map[string]any{"slot": slot, "layout_signature": layout.Signature}); e != nil {
		unlock()
		return nil, e
	}
	ok = true
	return c, nil
}
func (c *connection) reconnect(message string) error {
	automatic := !c.loader && automaticBootSupported(c.bootEnv)
	if automatic {
		body, e := c.console("restart-check")
		if e != nil {
			return fmt.Errorf("автоматический перезапуск остановлен: RAM storage не подтверждён как безопасно отключённый: %w", e)
		}
		if strings.TrimSpace(body) != "RESTART_READY" {
			return fmt.Errorf("автоматический перезапуск остановлен: неполный ответ проверки RAM storage")
		}
		c.b.Notify("Перезапускаю Капсулу для следующего этапа. USB-кабель не отключайте.")
		if e = c.phase("automatic-restart-requested", nil); e != nil {
			return e
		}
		body, e = c.console("restart")
		if e != nil || strings.TrimSpace(body) != "RESTART_ARMED" {
			// A lost console ACK cannot tell whether reset was already scheduled.
			// Never replay the command: first observe the loader, then offer fallback.
			if pe := c.phase("automatic-restart-ack-uncertain", nil); pe != nil {
				return pe
			}
		}
	}
	c.loaderN++
	folder := filepath.Join(c.run, fmt.Sprintf("loader-%d", c.loaderN))
	if e := c.t.SetFolder(folder); e != nil {
		return e
	}
	if e := c.phase("waiting-for-loader", nil); e != nil {
		return e
	}
	if automatic {
		if e := c.t.Wait(min(c.b.Wait, 30*time.Second)); e != nil {
			if !errors.Is(e, ErrLoaderTimeout) {
				return e
			}
			if ram, ok := c.t.(interface{ RAMAvailable() bool }); ok && ram.RAMAvailable() {
				body, checkErr := c.console("restart-check")
				if checkErr != nil {
					return fmt.Errorf("перед ручным переподключением не подтверждено отключение RAM storage: %w", checkErr)
				}
				if strings.TrimSpace(body) != "RESTART_READY" {
					return fmt.Errorf("перед ручным переподключением RAM storage не подтверждён")
				}
			}
			c.b.Notify("Автоматический перезапуск не вернул USB-загрузчик. Продолжим после ручного переподключения.")
			automatic = false
		}
	}
	if !automatic {
		if c.b.Reconnect == nil {
			return fmt.Errorf("требуется физическое переподключение: %s", message)
		}
		if e := c.b.Reconnect(message); e != nil {
			return e
		}
		if e := c.t.Wait(c.b.Wait); e != nil {
			return e
		}
	}
	bootEnv, tree, slot, e := c.t.Metadata()
	if e != nil {
		return e
	}
	layout, e := LayoutFromTree(tree)
	if e != nil {
		return e
	}
	id, e := identity(c.t)
	if e != nil {
		return e
	}
	if id != c.id || layout.Signature != c.layout.Signature {
		return fmt.Errorf("устройство/разметка изменились после переподключения")
	}
	if c.stockSlot != "" && c.stockSlot != slot {
		return fmt.Errorf("активный слот изменился; повторите подготовку по новой stock-системе")
	}
	c.slot = slot
	c.bootEnv = bootEnv
	c.loader = true
	return c.phase("loader-reconnected", map[string]any{"slot": slot})
}

// The known stock cold-boot branch opens only the short USB burning listener.
// Do not use the broader "update" branch, which can fall through to recovery.
func automaticBootSupported(env map[string]string) bool {
	return env["bootcmd"] == "run storeboot" &&
		env["switch_bootmode"] == "get_rebootmode;if test ${reboot_mode} = factory_reset; then run recovery_from_flash;else if test ${reboot_mode} = update; then run update;else if test ${reboot_mode} = cold_boot; then run try_auto_burn; else if test ${reboot_mode} = fastboot; then fastboot;fi;fi;fi;fi;" &&
		env["try_auto_burn"] == "update 700 450;" && strings.Contains(env["preboot"], "run switch_bootmode;") &&
		env["recovery_status"] != "in_progress" && env["upgrade_step"] != "3"
}
func (c *connection) ram(o RAMOptions) error {
	c.ramN++
	folder := filepath.Join(c.run, fmt.Sprintf("ram-%d", c.ramN))
	if e := PrivateDir(folder); e != nil {
		return e
	}
	o.Slot = c.slot
	o.Policy = c.b.Policy
	if e := c.phase("building-ram", map[string]any{"writable": o.Writable}); e != nil {
		return e
	}
	bundle, e := c.b.RAMBuilder(c.b.Resources, folder, o)
	if e != nil {
		return e
	}
	if e = c.t.Boot(bundle); e != nil {
		return e
	}
	c.bundle = bundle
	c.loader = false
	return c.phase("ram-boot-sent", nil)
}
func (c *connection) console(op string) (string, error) {
	if c.bundle.Nonce == "" {
		return "", fmt.Errorf("RAM-сеанс не создан")
	}
	c.reportN++
	folder := filepath.Join(c.run, fmt.Sprintf("report-%d-%s", c.reportN, op))
	if e := PrivateDir(folder); e != nil {
		return "", e
	}
	timeout := 600 * time.Second
	if op == "restart" || op == "restart-check" {
		timeout = 10 * time.Second
	}
	if op == "scan" {
		timeout = 1800 * time.Second
	}
	return c.t.Console(op, folder, c.bundle.Nonce, timeout)
}
func (c *connection) metadata(full bool) (Scan, error) {
	op := "metadata"
	if full {
		op = "scan"
	}
	body, e := c.console(op)
	if e != nil {
		return Scan{}, e
	}
	return ParseScan(body, full)
}
func (c *connection) loadProfile(rescan bool) error {
	if !rescan {
		if Exists(filepath.Join(c.device, "nand-map.json")) {
			var row BackupMap
			if e := ReadSealed(filepath.Join(c.device, "nand-map.json"), &row); e != nil {
				return e
			}
			if !row.Verified() {
				return fmt.Errorf("сохранённая карта не подтверждена")
			}
			c.profile = row.Profile
			c.backupVerified = true
		} else if Exists(filepath.Join(c.device, "device-profile.json")) {
			var row ProfileRecord
			if e := ReadSealed(filepath.Join(c.device, "device-profile.json"), &row); e != nil {
				return e
			}
			if row.Schema != 2 {
				return fmt.Errorf("неизвестная версия device profile")
			}
			c.profile = row.Profile
		}
	}
	if c.profile.Identity != "" {
		if e := c.profile.Validate(); e != nil {
			return e
		}
		if c.profile.Identity != c.id || c.profile.Layout != c.layout.Signature {
			return fmt.Errorf("профиль не соответствует подключённому устройству")
		}
		return c.t.Configure(c.profile.Geometry)
	}
	c.b.Notify("Определение геометрии и bad blocks: без чтения содержимого всей NAND.")
	if e := c.ram(RAMOptions{}); e != nil {
		return e
	}
	scan, e := c.metadata(false)
	if e != nil {
		return e
	}
	c.profile, e = PhysicalProfile(c.id, scan.Geometry, scan.Bad, c.layout)
	if e != nil {
		return e
	}
	if rescan && Exists(filepath.Join(c.device, "nand-map.json")) {
		if e = c.archiveState("nand-map.json", "explicit rescan: old backup remains archived; fresh metadata does not verify its contents"); e != nil {
			return e
		}
	}
	if e = SaveSealed(filepath.Join(c.device, "device-profile.json"), ProfileRecord{2, c.profile, "metadata-only; not a verified backup", Now()}); e != nil {
		return e
	}
	if e = c.t.Configure(c.profile.Geometry); e != nil {
		return e
	}
	return c.reconnect("Геометрия определена. Следующий этап использует индивидуальную разметку.")
}
func (c *connection) pair(name string, size int64, prefix string, compare bool) (string, ReadPair, error) {
	a, e := c.t.ReadStore(name, size, prefix+"-0.bin")
	if e != nil {
		return "", ReadPair{}, e
	}
	h, e := FileSHA(a)
	if e != nil {
		return "", ReadPair{}, e
	}
	ref, e := Ref(c.device, a)
	if e != nil {
		return "", ReadPair{}, e
	}
	row := ReadPair{[]Artifact{ref}, size, h, false}
	if compare {
		b, e := c.t.ReadStore(name, size, prefix+"-1.bin")
		if e != nil {
			return "", row, e
		}
		h, e = CompareECC(a, b, size)
		if e != nil {
			return "", row, e
		}
		other, e := Ref(c.device, b)
		if e != nil {
			return "", row, e
		}
		row.Reads = append(row.Reads, other)
		row.SHA = h
		row.Match = true
	}
	return a, row, nil
}
func (c *connection) backup(force bool) error {
	p := c.b.Policy
	if c.backupVerified && !force {
		c.out.Stages["backup"] = StageResult{"passed", "сохранённый проверенный бэкап"}
		return nil
	}
	if !p.Enabled("backup") {
		return nil
	}
	if !c.loader {
		return fmt.Errorf("бэкап требует loader")
	}
	g := c.profile.Geometry
	free, e := availableSpace(c.run)
	if e != nil {
		return e
	}
	required := 4*g.Size + 2*g.Size*g.OOB/g.Write + 64<<20
	if uint64(required) > free {
		return fmt.Errorf("недостаточно места для двух полных бэкапов NAND")
	}
	files := map[string]string{}
	logical := map[string]ReadPair{}
	reserved := map[string]ReadPair{}
	for _, part := range c.profile.Parts {
		if part.Name == "reserved" {
			continue
		}
		c.b.Notify("Сохранение ECC-чтений: " + part.Name)
		file, row, e := c.pair(part.Name, part.Logical, part.Name, p.Enabled("ecc-compare"))
		if e != nil {
			return e
		}
		files[part.Name] = file
		logical[part.Name] = row
	}
	for _, name := range sortedKeys(Reserved) {
		v := Reserved[name]
		a, e := c.t.ReadReserved(v[0], v[1], "reserved-"+name+"-0.bin")
		if e != nil {
			return e
		}
		h, e := FileSHA(a)
		if e != nil {
			return e
		}
		ref, e := Ref(c.device, a)
		if e != nil {
			return e
		}
		row := ReadPair{[]Artifact{ref}, v[1], h, false}
		if p.Enabled("ecc-compare") {
			b, e := c.t.ReadReserved(v[0], v[1], "reserved-"+name+"-1.bin")
			if e != nil {
				return e
			}
			if _, e = CompareECC(a, b, v[1]); e != nil {
				return e
			}
			ref, e := Ref(c.device, b)
			if e != nil {
				return e
			}
			row.Reads = append(row.Reads, ref)
			row.Match = true
		}
		reserved[name] = row
	}
	a, e := c.t.ReadRaw("nand-0.raw", c.b.Notify)
	if e != nil {
		return e
	}
	bb, e := c.t.ReadRaw("nand-1.raw", c.b.Notify)
	if e != nil {
		return e
	}
	raw, e := CompareRaw(a, bb, g.Size/g.Write*(g.Write+g.OOB))
	if e != nil {
		return e
	}
	ra, e := Ref(c.device, a)
	if e != nil {
		return e
	}
	rb, e := Ref(c.device, bb)
	if e != nil {
		return e
	}
	raw["reads"] = []Artifact{ra, rb}
	// No reconnect between the loader snapshots and this scan. In particular,
	// mutable misc/BCB bytes are compared within the same loader generation.
	if e = c.ram(RAMOptions{Profile: &c.profile}); e != nil {
		return e
	}
	full := p.Enabled("full-scan")
	scan, e := c.metadata(full)
	if e != nil {
		return e
	}
	if e = CheckMetadata(c.profile, scan, c.layout); e != nil {
		return e
	}
	if full {
		c.out.Stages["full-scan"] = StageResult{"passed", "после loader snapshots, без промежуточного cold boot"}
	}
	if p.Enabled("mapping-compare") {
		if e = VerifyMapping(c.profile, scan, files); e != nil {
			return e
		}
		c.out.Stages["mapping-compare"] = StageResult{Status: "passed"}
	}
	for i := 0; i < 2; i++ {
		metadata, e := c.metadata(false)
		if e != nil {
			return e
		}
		if e = CheckMetadata(c.profile, metadata, c.layout); e != nil {
			return e
		}
	}
	verified := p.Enabled("ecc-compare") && p.Enabled("mapping-compare")
	backup := map[string]any{"ecc_reads_match": p.Enabled("ecc-compare"), "physical_mapping_verified": p.Enabled("mapping-compare"), "metadata_passes_after_raw": 2, "logical": logical, "reserved": reserved, "raw": raw, "completed_at": Now(), "run": c.run, "read_epoch": "loader snapshots followed directly by RAM scan"}
	if e = AtomicJSON(filepath.Join(c.run, "backup.json"), backup); e != nil {
		return e
	}
	if verified {
		row := map[string]any{"schema": 1, "profile": c.profile, "backup": backup, "verified_at": Now()}
		if e = SaveSealed(filepath.Join(c.device, "nand-map.json"), row); e != nil {
			return e
		}
		c.backupVerified = true
	}
	c.out.Stages["backup"] = StageResult{"passed", "файлы сохранены; verified=" + strconv.FormatBool(verified)}
	if p.Enabled("ecc-compare") {
		c.out.Stages["ecc-compare"] = StageResult{Status: "passed"}
	}
	return c.phase("backup-complete", map[string]any{"backup_verified": verified})
}
func (c *connection) inspect() error {
	if c.loader {
		if e := c.ram(RAMOptions{Profile: &c.profile}); e != nil {
			return e
		}
		scan, e := c.metadata(false)
		if e != nil {
			return e
		}
		if e = CheckMetadata(c.profile, scan, c.layout); e != nil {
			return e
		}
	}
	body, e := c.console("inspect")
	if e != nil {
		return e
	}
	stock, e := ParseDeviceExport(body)
	if e != nil {
		return e
	}
	if stock.Installed {
		m := stock.InstalledManifest
		if (m == nil && stock.DeviceState != "preparing") || (m != nil && (m.Schema != 2 || m.Architecture != "aarch64" || m.Fixture || m.Identity != c.id || !digestRE.MatchString(m.ArchiveSHA))) {
			return fmt.Errorf("на устройстве неизвестный/чужой пакет; автоматическая установка запрещена")
		}
	}
	c.stock = stock
	c.stockSlot = c.slot
	return SaveSealed(filepath.Join(c.device, "stock-bundle.json"), map[string]any{"schema": 1, "identity": c.id, "slot": c.slot, "bundle": stock, "read_at": Now()})
}
func (c *connection) archiveState(name, reason string) error {
	source := filepath.Join(c.device, name)
	if !Exists(source) {
		return nil
	}
	target := filepath.Join(c.run, "superseded-"+name)
	if e := os.Rename(source, target); e != nil {
		return e
	}
	return AtomicJSON(filepath.Join(c.run, "superseded-"+name+".reason.json"), map[string]any{"reason": reason, "device_observation": "kernel-backed RO filesystem view", "at": Now()})
}
func (c *connection) reconcile() error {
	if !c.stock.Installed && Exists(filepath.Join(c.device, "installed.json")) {
		var old Installed
		if e := ReadSealed(filepath.Join(c.device, "installed.json"), &old); e != nil {
			return e
		}
		if old.State == "active" {
			if e := c.archiveState("installed.json", "на устройстве подтверждён stock после внешнего restore"); e != nil {
				return e
			}
		}
	}
	probe := filepath.Join(c.device, "probe.json")
	if Exists(probe) {
		var receipt Receipt
		if e := ReadSealed(probe, &receipt); e != nil {
			return e
		}
		if receipt.Identity != c.id || string(c.stock.Probe) != receipt.Token+"\n" {
			if e := c.archiveState("probe.json", "сохранённый probe больше не соответствует устройству"); e != nil {
				return e
			}
		}
	}
	return nil
}
func (c *connection) prepare(op string, rescan bool) error {
	if e := c.loadProfile(rescan); e != nil {
		return e
	}
	needsBackup := (op == "root" || op == "backup" || op == "update") && c.b.Policy.Enabled("backup") && (!c.backupVerified || op == "backup")
	if needsBackup {
		if e := c.backup(op == "backup"); e != nil {
			return e
		}
	} else if c.backupVerified && c.b.Policy.Enabled("backup") && op != "rollback" {
		c.out.Stages["backup"] = StageResult{"reused", "сохранённый проверенный бэкап"}
		for _, stage := range []string{"full-scan", "mapping-compare", "ecc-compare"} {
			if c.b.Policy.Enabled(stage) {
				c.out.Stages[stage] = StageResult{"reused", "доказательство из сохранённой проверенной карты"}
			}
		}
	} else {
		c.out.Stages["backup"] = StageResult{"skipped", "не требуется этой операцией/режимом"}
	}
	if c.b.Policy.Enabled("full-scan") && !needsBackup && ((!c.backupVerified && op != "rollback") || (op == "diagnose" && rescan)) {
		if c.loader {
			if e := c.ram(RAMOptions{Profile: &c.profile}); e != nil {
				return e
			}
		}
		scan, e := c.metadata(true)
		if e != nil {
			return e
		}
		if e = CheckMetadata(c.profile, scan, c.layout); e != nil {
			return e
		}
		c.out.Stages["full-scan"] = StageResult{Status: "passed"}
	}
	if e := c.inspect(); e != nil {
		return e
	}
	return c.reconcile()
}

type StorageEvidence struct {
	PreservedDirectories []string `json:"preserved_user_directories,omitempty"`
	PostSHA              string   `json:"post_write_sha256,omitempty"`
	TokenSHA             string   `json:"probe_token_sha256,omitempty"`
	Clean                bool     `json:"storage_clean"`
	ProbeRemount         bool     `json:"probe_remount_verified"`
	InstallRemount       bool     `json:"install_remount_verified"`
	ECC                  []uint64 `json:"ecc_corrected,omitempty"`
}

func ParseStorage(body, op, expected, token string, p Profile, policy Policy) (StorageEvidence, error) {
	var result StorageEvidence
	lines := []string{}
	for _, s := range strings.Split(body, "\n") {
		if s != "" {
			lines = append(lines, s)
		}
	}
	marker := map[string]string{"probe": "PROBE_PERSISTED", "probe-check": "PROBE_PERSISTED", "install": "OVERLAY_ACTIVATED", "refresh": "OVERLAY_ACTIVATED", "rollback": "OVERLAY_ROLLED_BACK"}[op]
	counts := map[string]int{}
	positions := map[string]int{}
	for i, s := range lines {
		counts[s]++
		positions[s] = i
	}
	if marker == "" || len(lines) == 0 || lines[len(lines)-1] != "STORAGE_CLEAN" || counts["STORAGE_CLEAN"] != 1 || counts[marker] != 1 {
		return result, fmt.Errorf("нет публикации/отката и clean detach")
	}
	data, e := p.Part("data")
	if e != nil {
		return result, e
	}
	var statsPositions []int
	hashPos := -1
	statsRE := regexp.MustCompile(`^good_blocks=(\d+) bad_blocks=(\d+) bytes=(\d+) corrected_delta=(\d+) failed_delta=(\d+)$`)
	hashRE := regexp.MustCompile(`^([0-9a-f]{64})  /run/capsula-data.bin$`)
	for i, line := range lines {
		if strings.HasPrefix(line, "PRESERVED_DIRECTORY ") {
			rel := strings.TrimPrefix(line, "PRESERVED_DIRECTORY ")
			if op != "rollback" || !regexp.MustCompile(`^[a-zA-Z0-9_./+\-]+$`).MatchString(rel) || strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
				return result, fmt.Errorf("неверный путь сохранённых пользовательских файлов")
			}
			result.PreservedDirectories = append(result.PreservedDirectories, rel)
		}
		if strings.HasPrefix(line, "good_blocks=") {
			m := statsRE.FindStringSubmatch(line)
			if m == nil {
				return result, fmt.Errorf("повреждены ECC stats")
			}
			v := []uint64{}
			for _, s := range m[1:] {
				n, e := strconv.ParseUint(s, 10, 64)
				if e != nil {
					return result, e
				}
				v = append(v, n)
			}
			if v[0] != uint64(data.Logical/Erase) || v[1] != uint64((data.Size-data.Logical)/Erase) || v[2] != uint64(data.Logical) || v[4] != 0 {
				return result, fmt.Errorf("неверные размер/геометрия/ECC data")
			}
			result.ECC = append(result.ECC, v[3])
			statsPositions = append(statsPositions, i)
		}
		if m := hashRE.FindStringSubmatch(line); m != nil {
			if hashPos >= 0 {
				return result, fmt.Errorf("повторный post-write hash")
			}
			hashPos = i
			result.PostSHA = m[1]
		}
	}
	wantStats := 0
	if policy.Enabled("data-compare") {
		wantStats++
		match := "DATA_MATCH " + expected
		if counts[match] != 1 || positions[match] >= positions[marker] || len(statsPositions) == 0 || statsPositions[0] >= positions[match] {
			return result, fmt.Errorf("нет loader/RAM data evidence до записи")
		}
	}
	if policy.Enabled("post-verify") {
		wantStats++
		if hashPos <= positions[marker] || len(statsPositions) == 0 || statsPositions[len(statsPositions)-1] <= positions[marker] || statsPositions[len(statsPositions)-1] >= hashPos {
			return result, fmt.Errorf("нет полного post-write чтения после detach")
		}
	} else if result.PostSHA != "" {
		return result, fmt.Errorf("неожиданное evidence пропущенного post-verify")
	}
	if len(statsPositions) != wantStats {
		return result, fmt.Errorf("неверное число ECC чтений data")
	}
	if op == "probe" || op == "probe-check" {
		result.ProbeRemount = true
		result.TokenSHA = SHA([]byte(token + "\n"))
		if counts["PROBE_TOKEN "+result.TokenSHA] != 1 {
			return result, fmt.Errorf("RAM remount не подтвердил индивидуальный probe token")
		}
	}
	if (op == "install" || op == "refresh") && policy.Enabled("post-verify") {
		if counts["INSTALL_REMOUNT_VERIFIED"] != 1 || positions["INSTALL_REMOUNT_VERIFIED"] >= positions[marker] {
			return result, fmt.Errorf("нет remount проверки установки")
		}
		result.InstallRemount = true
	}
	if op == "rollback" {
		if counts["PROBE_REMOVED"] != 1 || positions["PROBE_REMOVED"] >= positions[marker] {
			return result, fmt.Errorf("не подтверждён полный откат")
		}
		if policy.Enabled("post-verify") && (counts["ROLLBACK_REMOUNT_VERIFIED"] != 1 || positions["ROLLBACK_REMOUNT_VERIFIED"] >= positions["PROBE_REMOVED"]) {
			return result, fmt.Errorf("не подтверждён rollback remount")
		}
	}
	result.Clean = true
	return result, nil
}
func (c *connection) write(op, packagePath, token string) (StorageEvidence, error) {
	var evidence StorageEvidence
	if !c.loader {
		return evidence, fmt.Errorf("запись требует loader-подключения")
	}
	if c.b.BeforeWrite != nil {
		if e := c.b.BeforeWrite(c.id, op, c.b.Policy); e != nil {
			return evidence, e
		}
	}
	expected := ""
	if c.b.Policy.Enabled("data-compare") {
		part, e := c.profile.Part("data")
		if e != nil {
			return evidence, e
		}
		_, pair, e := c.pair("data", part.Logical, op+"-fresh-data", c.b.Policy.Enabled("ecc-compare"))
		if e != nil {
			return evidence, e
		}
		expected = pair.SHA
		if pair.Match {
			c.out.Stages["ecc-compare"] = StageResult{"passed", "свежая пара ECC-чтений data"}
		}
	}
	if op == "rollback" && token == "" {
		// A legacy installation may lack durable probe.sha256. The RO kernel
		// inspection supplies its actual marker, independent of any host receipt.
		token = strings.TrimSuffix(string(c.stock.Probe), "\n")
	}
	options := RAMOptions{Operation: op, Profile: &c.profile, Writable: true, Expected: expected, Token: token, Package: packagePath}

	if e := c.ram(options); e != nil {
		return evidence, e
	}
	scan, e := c.metadata(false)
	if e != nil {
		return evidence, e
	}
	if e = CheckMetadata(c.profile, scan, c.layout); e != nil {
		return evidence, e
	}
	if packagePath != "" && c.b.Policy.Enabled("stock-compare") {
		body, e := c.console("stock")
		if e != nil {
			return evidence, e
		}
		if e = checkStockHashes(body, c.stock); e != nil {
			return evidence, e
		}
		c.out.Stages["stock-compare"] = StageResult{Status: "passed"}
	}
	if e = c.phase("writing-"+op, nil); e != nil {
		return evidence, e
	}
	body, e := c.console(op)
	if e != nil {
		return evidence, e
	}
	evidence, e = ParseStorage(body, op, expected, token, c.profile, c.b.Policy)
	if e != nil {
		return evidence, e
	}
	c.out.StorageClean = evidence.Clean
	for _, rel := range evidence.PreservedDirectories {
		c.b.Notify("Сохранены пользовательские файлы в /data/overlay/upper/" + rel)
	}
	for _, stage := range []string{"data-compare", "post-verify"} {
		if c.b.Policy.Enabled(stage) {
			c.out.Stages[stage] = StageResult{Status: "passed"}
		}
	}
	if packagePath != "" {
		for _, stage := range []string{"package-hash", "space", "conflicts"} {
			if c.b.Policy.Enabled(stage) {
				c.out.Stages[stage] = StageResult{Status: "passed"}
			}
		}
	}
	if e = AtomicJSON(filepath.Join(c.run, "storage-"+op+".json"), evidence); e != nil {
		return evidence, e
	}
	return evidence, c.phase("storage-complete", nil)
}
func checkStockHashes(body string, stock StockBundle) error {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 5 || lines[len(lines)-1] != "STOCK_CLEAN" {
		return fmt.Errorf("неполный stock hash report")
	}
	seen := map[string]bool{}
	for _, line := range lines[:len(lines)-1] {
		parts := strings.SplitN(line, "  /stock", 2)
		if len(parts) != 2 || seen[parts[1]] || !digestRE.MatchString(parts[0]) {
			return fmt.Errorf("повреждён stock hash report")
		}
		want, ok := stock.Files[parts[1]]
		if !ok || SHA(want) != parts[0] {
			return fmt.Errorf("stock-система изменилась после подготовки; запись остановлена")
		}
		seen[parts[1]] = true
	}
	return nil
}
func (c *connection) profileSHA() string { b, _ := Canonical(c.profile); return SHA(b) }
func (c *connection) loadReceipt() (Receipt, error) {
	var r Receipt
	if e := ReadSealed(filepath.Join(c.device, "probe.json"), &r); e != nil {
		return r, e
	}
	if r.Identity != c.id || r.ProfileSHA != c.profileSHA() || !digestRE.MatchString(r.Token) {
		return r, fmt.Errorf("квитанция probe не соответствует устройству")
	}
	return r, nil
}
func (c *connection) probe() (Receipt, error) {
	if Exists(filepath.Join(c.device, "probe.json")) {
		r, e := c.loadReceipt()
		if e != nil {
			return r, e
		}
		if string(c.stock.Probe) == r.Token+"\n" {
			if !r.Audited && (!r.Remount || r.TokenSHA != SHA([]byte(r.Token+"\n"))) {
				if !c.loader {
					if e = c.reconnect("Подтверждение старой квитанции probe штатным remount, без замены маркера."); e != nil {
						return r, e
					}
				}
				evidence, e := c.write("probe-check", "", r.Token)
				if e != nil {
					return r, e
				}
				r.PostSHA = evidence.PostSHA
				r.Remount = evidence.ProbeRemount
				r.TokenSHA = evidence.TokenSHA
				r.Run = c.run
				if e = SaveSealed(filepath.Join(c.device, "probe.json"), r); e != nil {
					return r, e
				}
			}
			c.out.Stages["probe"] = StageResult{"passed", "токен подтверждён текущим kernel-backed просмотром"}
			return r, nil
		}
	}
	if len(c.stock.Probe) > 0 {
		if c.stock.Installed && c.stock.DeviceState == "active" && c.stock.InstalledManifest.Identity == c.id {
			if e := validateInstalledIndex(c.stock); e != nil {
				return Receipt{}, e
			}
			if len(c.stock.ProbeProof) > 0 && strings.TrimSpace(string(c.stock.ProbeProof)) != SHA(c.stock.Probe) {
				return Receipt{}, fmt.Errorf("on-device proof не соответствует probe marker")
			}
			r := Receipt{Identity: c.id, ProfileSHA: c.profileSHA(), Token: strings.TrimSpace(string(c.stock.Probe)), Run: c.run}
			if e := SaveSealed(filepath.Join(c.device, "probe.json"), r); e != nil {
				return Receipt{}, e
			}
			c.b.Notify("Пробная запись обнаружена на колонке; повторная проверка сохранности и независимая сверка выполняются заново.")
			return c.probe()
		}
		return Receipt{}, fmt.Errorf("на устройстве неизвестный probe; не удаляйте state, требуется разбор его происхождения")
	}
	if !c.loader {
		if e := c.reconnect("Следующий этап — пробная запись в data."); e != nil {
			return Receipt{}, e
		}
	}
	token := RandomHex(32)
	evidence, e := c.write("probe", "", token)
	if e != nil {
		return Receipt{}, e
	}
	r := Receipt{c.id, c.profileSHA(), token, evidence.PostSHA, false, evidence.TokenSHA, evidence.ProbeRemount, c.run}
	if e = SaveSealed(filepath.Join(c.device, "probe.json"), r); e != nil {
		return r, e
	}
	c.out.Stages["probe"] = StageResult{Status: "passed"}
	return r, nil
}
func (c *connection) auditProbe(r *Receipt) error {
	if r.Audited {
		c.out.Stages["probe-audit"] = StageResult{"passed", "сохранённая квитанция + текущий токен устройства"}
		return nil
	}
	if !r.Remount || r.TokenSHA != SHA([]byte(r.Token+"\n")) || !digestRE.MatchString(r.PostSHA) {
		return fmt.Errorf("нет отдельного доказательства remount/token/post-read для аудита probe")
	}
	if !c.loader {
		if e := c.reconnect("Пробный файл сохранён. Следующий этап — независимое чтение загрузчиком."); e != nil {
			return e
		}
	}
	part, e := c.profile.Part("data")
	if e != nil {
		return e
	}
	_, pair, e := c.pair("data", part.Logical, "audit-data", true)
	if e != nil {
		return fmt.Errorf("probe: два независимых чтения data не совпали: %w", e)
	}
	if pair.SHA != r.PostSHA {
		return fmt.Errorf("probe: loader hash data не совпал с RAM post-detach hash; remount/token были проверены отдельно")
	}
	r.Audited = true
	if e = SaveSealed(filepath.Join(c.device, "probe.json"), r); e != nil {
		return e
	}
	c.out.Stages["probe-audit"] = StageResult{Status: "passed"}
	return nil
}
func (b *Backend) Execute(op string, rescan bool) (out *Outcome, err error) {
	if op != "root" && op != "backup" && op != "diagnose" && op != "update" && op != "rollback" {
		return nil, fmt.Errorf("неизвестная операция")
	}

	c, e := b.connect(op)
	if e != nil {
		return nil, e
	}
	out = c.out
	defer func() { c.finish(err) }()
	if err = c.prepare(op, rescan); err != nil {
		return
	}
	if op == "diagnose" || op == "backup" {
		return
	}
	if op == "root" && c.stock.Installed {
		err = fmt.Errorf("на устройстве уже установлен продукт (состояние %s); используйте update или rollback", c.stock.DeviceState)
		return
	}
	if op == "update" && !c.stock.Installed {
		err = fmt.Errorf("на устройстве stock; используйте root")
		return
	}
	if op == "update" {
		if c.stock.DeviceState != "active" {
			err = fmt.Errorf("прерванная установка: сначала rollback")
			return
		}
		if err = c.recoverCredentials(); err != nil {
			return
		}
	}
	var receipt Receipt
	if op != "rollback" && b.Policy.Enabled("probe") {
		receipt, err = c.probe()
		if err != nil {
			return
		}
		if b.Policy.Enabled("probe-audit") {
			if err = c.auditProbe(&receipt); err != nil {
				return
			}
		}
	} else if Exists(filepath.Join(c.device, "probe.json")) {
		receipt, err = c.loadReceipt()
		if err != nil {
			return
		}
	}
	if op == "rollback" && !c.stock.Installed {
		err = fmt.Errorf("нет установленного продукта для отката")
		return
	}
	if op == "update" {
		b.Notify("Обновление заменит файлы пакета релизными версиями, включая изменённые вручную. Файлы вне пакета сохраняются.")
		if b.Policy.Enabled("data-compare") {
			b.Notify("Прежнее состояние останется в свежем снимке data этого сеанса.")
		}
	}
	packagePath := ""

	var manifest *Manifest
	if op != "rollback" {
		packagePath = filepath.Join(c.run, "package")
		if b.Password == nil {
			err = fmt.Errorf("недоступен локальный ввод пароля")
			return
		}
		manifest, err = b.PackageBuilder(b.Resources, packagePath, c.device, c.id, c.stock, b.Password, b.Policy.Enabled("package-hash"))
		if err != nil {
			return
		}
	}
	if !c.loader {
		if err = c.reconnect("Следующий этап — " + map[string]string{"root": "установка", "update": "обновление", "rollback": "откат"}[op] + ". USB не отключайте после начала записи."); err != nil {
			return
		}
	}
	storageOp := map[string]string{"root": "install", "update": "refresh", "rollback": "rollback"}[op]
	var evidence StorageEvidence
	evidence, err = c.write(storageOp, packagePath, receipt.Token)
	if err != nil {
		return
	}
	if op == "rollback" {
		i := Installed{State: "rolled_back", Identity: c.id, Run: c.run, Policy: &b.Policy}
		if err = SaveSealed(filepath.Join(c.device, "installed.json"), i); err != nil {
			return
		}
		if Exists(filepath.Join(c.device, "probe.json")) {
			err = c.archiveState("probe.json", "product rollback completed")
		}
		return
	}
	pub, e := os.ReadFile(filepath.Join(packagePath, "server-hostkey.pub"))
	if e != nil {
		err = e
		return
	}
	rel, e := filepath.Rel(c.device, packagePath)
	if e != nil {
		err = e
		return
	}
	credentials := map[string]string{}
	for _, name := range []string{"hostkey", "root-password.hash"} {
		credentials[name], err = FileSHA(filepath.Join(c.device, "credentials", name))
		if err != nil {
			return
		}
	}
	i := Installed{Version: manifest.Version, State: "active", Identity: c.id, Package: filepath.ToSlash(rel), ArchiveSHA: manifest.ArchiveSHA, PublicKey: strings.TrimSpace(string(pub)), CredentialHashes: credentials, Run: c.run, Policy: &b.Policy}
	if err = SaveSealed(filepath.Join(c.device, "installed.json"), i); err != nil {
		return
	}
	out.InstallationCompleted = true
	out.Version = manifest.Version
	out.StorageClean = evidence.Clean
	return
}
