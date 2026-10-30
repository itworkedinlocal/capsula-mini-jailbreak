package capsula

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func releaseModeMatches(_ os.FileInfo, _ int64) bool { return true }

func (r Resources) checkHost() error {
	var pins struct {
		Files map[string]struct {
			SHA string `json:"sha256"`
		} `json:"files"`
	}
	if err := readJSON(r.Stock("host-windows.json"), &pins); err != nil {
		return err
	}
	if len(pins.Files) != 1 {
		return fmt.Errorf("неполный Windows комплект")
	}
	return r.Pinned(r.Stock("bin/windows-x86_64/password-hash.exe"), pins.Files["password-hash.exe"].SHA)
}

func (r Resources) Native(name string, args []string, input []byte) ([]byte, error) {
	if name == "password-hash" && len(args) == 0 {
		if err := r.checkHost(); err != nil {
			return nil, err
		}
		cmd := exec.Command(r.Stock("bin/windows-x86_64/password-hash.exe"))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("password helper: %w", err)
		}
		return out, nil
	}
	if name == "dropbearmulti" && len(args) == 5 && args[0] == "dropbearkey" && args[1] == "-t" && args[2] == "ed25519" && args[3] == "-f" {
		key, err := newDropbearKey()
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return nil, writePrivateExclusive(args[4], key)
	}
	if name == "dropbearmulti" && len(args) == 4 && args[0] == "dropbearkey" && args[1] == "-y" && args[2] == "-f" {
		f, err := openPrivate(filepath.Clean(args[3]))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		key, err := io.ReadAll(io.LimitReader(f, 84))
		if err != nil {
			return nil, err
		}
		defer clear(key)
		pub, err := dropbearPublic(key)
		if err != nil {
			return nil, err
		}
		return []byte(pub + "\n"), nil
	}
	return nil, fmt.Errorf("неподдерживаемый native helper %s", name)
}
