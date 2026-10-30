package capsula

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const KernelSHA = "7a155fcd0fbab5af149094f408e3bbb2209d478e4adac924659cd2b049014226"
const HelperSHA = "aa03cad4b8561bd376450bae702cfaa69eb1b4f4346ccff719af2864e90b6799"

type Resources struct {
	Root string
	Logo string
}

func LocateResources() (Resources, error) {
	exe, e := os.Executable()
	if e != nil {
		return Resources{}, e
	}
	exe, _ = filepath.EvalSymlinks(exe)
	cwd, _ := os.Getwd()
	for _, root := range []string{filepath.Join(filepath.Dir(exe), "resources"), filepath.Join(cwd, "resources"), filepath.Join(filepath.Dir(exe), "..", "resources")} {
		if Exists(filepath.Join(root, "ramboot/ramboot-manifest.json")) {
			root, _ = filepath.Abs(root)
			return Resources{root, filepath.Join(root, "fastfetch.jsonc")}, nil
		}
	}
	return Resources{}, fmt.Errorf("не найден комплект ресурсов; распакуйте весь архив")
}
func (r Resources) Stock(name string) string {
	return filepath.Join(r.Root, "stock-root", filepath.FromSlash(name))
}
func (r Resources) RAM(name string) string { return filepath.Join(r.Root, "ramboot", name) }
func readJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if e = UniqueJSON(b); e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (r Resources) Pinned(path, sha string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ресурс не является обычным файлом: %s", path)
	}
	got, e := FileSHA(path)
	if e != nil {
		return e
	}
	if !digestRE.MatchString(sha) || got != sha {
		return fmt.Errorf("изменён закреплённый ресурс: %s", path)
	}
	return nil
}
func (r Resources) Check() error {
	if e := r.checkRelease(); e != nil {
		return e
	}
	if e := r.Pinned(r.RAM("Image"), KernelSHA); e != nil {
		return e
	}
	if e := r.checkHost(); e != nil {
		return e
	}
	var pins struct {
		Files map[string]struct {
			SHA string `json:"sha256"`
		} `json:"files"`
	}
	if e := readJSON(r.RAM("ramboot-manifest.json"), &pins); e != nil {
		return e
	}
	for _, name := range []string{"vk-mini-a113x-usb-only.dtb", "initramfs.cpio.gz"} {
		if e := r.Pinned(r.RAM(name), pins.Files[name].SHA); e != nil {
			return e
		}
	}
	var helpers map[string]struct {
		SHA string `json:"sha256"`
	}
	if e := readJSON(r.Stock("helpers-build.json"), &helpers); e != nil {
		return e
	}
	for _, name := range []string{"aarch64/nand-agent", "aarch64/ubi-control", "aarch64/directory-times", "aarch64/ram-restart"} {
		if e := r.Pinned(r.Stock("bin/"+name), helpers[name].SHA); e != nil {
			return e
		}
	}
	for _, arch := range []string{"aarch64"} {
		var tk Toolkit
		if e := readJSON(r.Stock("toolkit/"+arch+"/manifest.json"), &tk); e != nil {
			return e
		}
		if !tk.Complete || tk.Architecture != arch || !tk.Static {
			return fmt.Errorf("неполный toolkit %s", arch)
		}
		for name, row := range tk.Files {
			if e := SafePackagePath("usr/lib/capsula-root/" + name); e != nil {
				return e
			}
			if e := r.Pinned(r.Stock("toolkit/"+arch+"/"+name), row.SHA); e != nil {
				return e
			}
		}
	}
	var logo any
	if e := readJSON(r.Logo, &logo); e != nil {
		return fmt.Errorf("Fastfetch config: %w", e)
	}
	return nil
}

func (r Resources) checkRelease() error {
	base := filepath.Dir(r.Root)
	name := filepath.Join(base, "release-manifest.json")
	if !Exists(name) {
		return nil
	}
	var record struct {
		Files map[string]FileRecord `json:"files"`
	}
	if e := readJSON(name, &record); e != nil {
		return e
	}
	if len(record.Files) == 0 {
		return fmt.Errorf("пустой release manifest")
	}
	for name, row := range record.Files {
		p, e := SafeJoin(base, name)
		if e != nil {
			return e
		}
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !i.Mode().IsRegular() || i.Size() != row.Bytes || !releaseModeMatches(i, row.Mode) {
			return fmt.Errorf("изменён release member: %s", name)
		}
		if e = r.Pinned(p, row.SHA); e != nil {
			return e
		}
	}
	return nil
}
