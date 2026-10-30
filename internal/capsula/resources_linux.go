package capsula

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func releaseModeMatches(i os.FileInfo, mode int64) bool { return int64(i.Mode().Perm()) == mode }
func (r Resources) checkHost() error {
	if e := r.Pinned(filepath.Join(r.Root, "update"), HelperSHA); e != nil {
		return e
	}
	var helpers map[string]struct {
		SHA string `json:"sha256"`
	}
	if e := readJSON(r.Stock("helpers-build.json"), &helpers); e != nil {
		return e
	}
	if e := r.Pinned(r.Stock("bin/x86_64/password-hash"), helpers["x86_64/password-hash"].SHA); e != nil {
		return e
	}
	var usb struct {
		Files map[string]struct {
			SHA string `json:"sha256"`
		} `json:"files"`
	}
	if e := readJSON(r.Stock("host-usb.json"), &usb); e != nil {
		return e
	}
	if len(usb.Files) != 2 {
		return fmt.Errorf("неполный USB комплект")
	}
	for _, name := range []string{"libusb-0.1.so.4", "libusb-1.0.so.0"} {
		if e := r.Pinned(r.Stock("bin/x86_64/"+name), usb.Files[name].SHA); e != nil {
			return e
		}
	}
	return nil
}
func (r Resources) Native(name string, args []string, input []byte) ([]byte, error) {
	p := r.Stock("bin/x86_64/" + name)
	var sha string
	if name == "dropbearmulti" {
		var pins struct {
			Binaries map[string]struct {
				SHA string `json:"sha256"`
			} `json:"binaries"`
		}
		if e := readJSON(r.Stock("dropbear-build.json"), &pins); e != nil {
			return nil, e
		}
		sha = pins.Binaries["x86_64"].SHA
	} else {
		var pins map[string]struct {
			SHA string `json:"sha256"`
		}
		if e := readJSON(r.Stock("helpers-build.json"), &pins); e != nil {
			return nil, e
		}
		sha = pins["x86_64/"+name].SHA
	}
	if e := r.Pinned(p, sha); e != nil {
		return nil, e
	}
	cmd := exec.Command(p, args...)
	cmd.Stdin = strings.NewReader(string(input))
	out, e := cmd.Output()
	if e != nil {
		return nil, fmt.Errorf("native helper %s: %w", name, e)
	}
	return out, nil
}
