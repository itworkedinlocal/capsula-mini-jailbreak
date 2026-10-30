package capsula

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/u-root/u-root/pkg/dt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Transport interface {
	SetFolder(string) error
	Wait(time.Duration) error
	Metadata() (map[string]string, *dt.FDT, string, error)
	Configure(Geometry) error
	ReadStore(string, int64, string) (string, error)
	ReadReserved(int64, int64, string) (string, error)
	ReadRaw(string, func(string)) (string, error)
	Boot(RAMBundle) error
	Console(string, string, string, time.Duration) (string, error)
	Close()
}

var ErrLoaderTimeout = errors.New("USB loader timeout")

type USB struct {
	platform usbPlatform
	r        Resources
	folder   string
	ctx      context.Context
	notify   func(string)
	release  func()
	geometry Geometry
	memory   map[uint32][]byte
	bulk     map[string]bool
	stores   map[string]int64
}

func (u *USB) Close() {
	u.closePlatform()
	u.closeSetup()
	if u.release != nil {
		u.release()
		u.release = nil
	}
}

// Prepare runs before the initial connection instructions. Transport models
// need not implement it; Linux only uses it to route notices through the UI.
func (u *USB) Prepare(notify func(string)) error {
	u.notify = notify
	return u.preparePlatform()
}

func (u *USB) notice(message string) {
	if u.notify != nil {
		u.notify(message)
	} else {
		usbNotice(message)
	}
}
func (u *USB) SetFolder(p string) error {
	if e := PrivateDir(p); e != nil {
		return e
	}
	u.folder = p
	return nil
}
func (u *USB) Configure(g Geometry) error {
	if e := g.Validate(); e != nil {
		return e
	}
	u.geometry = g
	return nil
}
func (u *USB) output(name string, reuse bool) (string, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) || name == "." || name == ".." {
		return "", fmt.Errorf("неверное имя снимка")
	}
	p := filepath.Join(u.folder, name)
	if i, e := os.Lstat(p); e == nil {
		if !i.Mode().IsRegular() || !reuse {
			return "", fmt.Errorf("снимок существует/подменён")
		}
		if e = os.Remove(p); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	return p, nil
}
func (u *USB) validate(a []string) error {
	if len(a) == 2 && a[0] == "identify" && a[1] == "7" {
		return nil
	}
	if len(a) == 2 && a[0] == "bulkcmd" {
		if u.bulk[a[1]] {
			return nil
		}
		if a[1] == "echo; nand read 0x1080000 0x400000 0x100000" {
			return nil
		}
		if u.geometry.Size > 0 {
			m := regexp.MustCompile(`^echo; nand (read|read\.raw) 0x1080000 (0x[0-9a-f]+) (0x[0-9a-f]+)$`).FindStringSubmatch(a[1])
			if m != nil {
				off, _ := strconv.ParseInt(m[2], 0, 64)
				n, _ := strconv.ParseInt(m[3], 0, 64)
				size := n
				if m[1] == "read.raw" {
					size = n * 2048
				}
				if off%Erase == 0 && size > 0 && size <= 0x800000 && size%Erase == 0 && off+size <= u.geometry.Size {
					return nil
				}
			}
		}
	}
	if len(a) == 6 && a[0] == "mread" && a[3] == "normal" {
		n, e := strconv.ParseInt(a[4], 0, 64)
		if e != nil || n <= 0 || filepath.Dir(a[5]) != u.folder {
			return fmt.Errorf("недопустимый USB read")
		}
		if a[1] == "store" && u.stores[a[2]] == n {
			return nil
		}
		if a[1] == "mem" {
			addr, e := strconv.ParseUint(a[2], 0, 32)
			if e != nil {
				return e
			}
			if (addr == 0x4000000 && n == 2048) || (addr == 0x2000000 && n == 131072) || (addr == 0x1000000 && n == 65536) || (addr == 0x1080000 && n == 0x100000) {
				return nil
			}
			if addr == 0x1080000 && u.geometry.Size > 0 && n <= 0x840000 {
				return nil
			}
			if b, ok := u.memory[uint32(addr)]; ok && int64(len(b)) == n {
				return nil
			}
		}
	}
	if len(a) == 5 && a[0] == "mwrite" && a[2] == "mem" && a[4] == "normal" {
		addr, e := strconv.ParseUint(a[3], 0, 32)
		if e == nil {
			b, e := os.ReadFile(a[1])
			if e == nil && len(b) > 0 && bytes.Equal(b, u.memory[uint32(addr)]) {
				return nil
			}
		}
	}
	return fmt.Errorf("команда вне разрешённого USB протокола")
}
func waitContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (u *USB) readMemory(addr uint32, size int64, name string) ([]byte, error) {
	p, e := u.output(name, true)
	if e != nil {
		return nil, e
	}
	if _, e = u.call([]string{"mread", "mem", fmt.Sprintf("0x%x", addr), "normal", fmt.Sprintf("0x%x", size), p}, false); e != nil {
		return nil, e
	}
	i, e := os.Stat(p)
	if e != nil {
		return nil, e
	}
	if i.Size() != size {
		return nil, fmt.Errorf("укороченное USB чтение RAM")
	}
	return os.ReadFile(p)
}
func (u *USB) Metadata() (map[string]string, *dt.FDT, string, error) {
	env := map[string]string{}
	if _, e := u.call([]string{"bulkcmd", "env export -t 0x2000000"}, false); e != nil {
		return nil, nil, "", e
	}
	body, e := u.readMemory(0x2000000, 131072, "environment-private.bin")
	if e != nil {
		return nil, nil, "", e
	}
	body = bytes.SplitN(body, []byte{0}, 2)[0]
	for _, b := range body {
		if b > 127 {
			return nil, nil, "", fmt.Errorf("неверная кодировка env")
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			continue
		}
		if _, ok := env[pair[0]]; ok {
			return nil, nil, "", fmt.Errorf("повторный ключ env")
		}
		env[pair[0]] = pair[1]
	}
	slot := env["boot_part"]
	if env["bootcmd"] != "run storeboot" || (slot != "boot_a" && slot != "boot_b") {
		return nil, nil, "", fmt.Errorf("ожидается stock bootcmd и слот A/B")
	}
	command := "imgread dtb " + slot + " 0x1000000"
	u.bulk[command] = true
	if _, e = u.call([]string{"bulkcmd", command}, false); e != nil {
		return nil, nil, "", e
	}
	a, e := u.readMemory(0x1000000, 65536, "stock-dtb-0.bin")
	if e != nil {
		return nil, nil, "", e
	}
	b, e := u.readMemory(0x1000000, 65536, "stock-dtb-1.bin")
	if e != nil {
		return nil, nil, "", e
	}
	if !bytes.Equal(a, b) || len(a) < 40 {
		return nil, nil, "", fmt.Errorf("DTB не совпал при двойном чтении")
	}
	size := binary.BigEndian.Uint32(a[4:])
	if size < 40 || size > 65536 {
		return nil, nil, "", fmt.Errorf("неверный размер DTB")
	}
	tree, e := ReadTree(a[:size])
	return env, tree, slot[len(slot)-1:], e
}
func (u *USB) ReadStore(name string, size int64, file string) (string, error) {
	known := false
	for _, n := range append([]string{"bootloader"}, NormalNames...) {
		if n == name {
			known = true
		}
	}
	if !known || size <= 0 {
		return "", fmt.Errorf("неверный раздел")
	}
	u.stores[name] = size
	p, e := u.output(file, false)
	if e != nil {
		return "", e
	}
	if _, e = u.call([]string{"mread", "store", name, "normal", fmt.Sprintf("0x%x", size), p}, false); e != nil {
		return "", e
	}
	i, e := os.Stat(p)
	if e != nil {
		return "", e
	}
	if i.Size() != size {
		return "", fmt.Errorf("укороченное чтение %s", name)
	}
	return p, nil
}
func (u *USB) ReadReserved(off, size int64, file string) (string, error) {
	found := false
	for _, v := range Reserved {
		if v == [2]int64{off, size} {
			found = true
		}
	}
	if !found || (u.geometry.Size == 0 && off != 0x400000) {
		return "", fmt.Errorf("служебная область не разрешена")
	}
	if _, e := u.call([]string{"bulkcmd", fmt.Sprintf("echo; nand read 0x1080000 %#x %#x", off, size)}, false); e != nil {
		return "", e
	}
	_, e := u.readMemory(0x1080000, size, file)
	return filepath.Join(u.folder, file), e
}
func (u *USB) ReadRaw(file string, notify func(string)) (string, error) {
	if u.geometry.Size == 0 {
		return "", fmt.Errorf("не определена геометрия")
	}
	p, e := u.output(file, false)
	if e != nil {
		return "", e
	}
	out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	defer out.Close()
	for off := int64(0); off < u.geometry.Size; off += 0x800000 {
		size := min(int64(0x800000), u.geometry.Size-off)
		pages := size / 2048
		if _, e = u.call([]string{"bulkcmd", fmt.Sprintf("echo; nand read.raw 0x1080000 %#x %#x", off, pages)}, false); e != nil {
			return "", e
		}
		b, e := u.readMemory(0x1080000, pages*2112, "raw-chunk.bin")
		if e != nil {
			return "", e
		}
		if _, e = out.Write(b); e != nil {
			return "", e
		}
		notify(fmt.Sprintf("RAW/OOB: %d%%", (off+size)*100/u.geometry.Size))
	}
	if e = out.Sync(); e != nil {
		return "", e
	}
	return p, nil
}
func (u *USB) Boot(bundle RAMBundle) error {
	u.memory = map[uint32][]byte{}
	for _, a := range bundle.Assets {
		b, e := os.ReadFile(a.Path)
		if e != nil {
			return e
		}
		padded := make([]byte, (len(b)+2047)&^2047)
		copy(padded, b)
		for off := 0; off < len(padded); off += 0x800000 {
			u.memory[a.Address+uint32(off)] = padded[off:min(len(padded), off+0x800000)]
		}
	}
	commands := []string{}
	for i, word := range bundle.Words {
		prefix := ""
		if i > 0 {
			prefix = "${bootargs} "
		}
		command := "echo; setenv bootargs " + prefix + word
		if len(command) > 63 {
			return fmt.Errorf("слишком длинная bootarg")
		}
		commands = append(commands, command)
		u.bulk[command] = true
	}
	boot := "echo; booti 0x1080000 0x4000000 0x1000000"
	u.bulk[boot] = true
	tmp, e := os.MkdirTemp("", "capsula-ram-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	chunk := filepath.Join(tmp, "chunk")
	for _, a := range bundle.Assets {
		b, e := os.ReadFile(a.Path)
		if e != nil {
			return e
		}
		paddedLength := (len(b) + 2047) &^ 2047
		for off := 0; off < paddedLength; off += 0x800000 {
			addr := a.Address + uint32(off)
			content := u.memory[addr]
			if e = os.WriteFile(chunk, content, 0600); e != nil {
				return e
			}
			if _, e = u.call([]string{"mwrite", chunk, "mem", fmt.Sprintf("0x%x", addr), "normal"}, false); e != nil {
				return e
			}
			if e = u.verifyMemory(addr, content); e != nil {
				return e
			}
		}
		u.notice("RAM передана и проверена: " + filepath.Base(a.Path))
	}
	for addr, content := range u.memory {
		if e = u.verifyMemory(addr, content); e != nil {
			return e
		}
	}
	for _, command := range commands {
		if _, e = u.call([]string{"bulkcmd", command}, false); e != nil {
			return e
		}
	}
	_, e = u.call([]string{"bulkcmd", boot}, true)
	return e
}
func (u *USB) verifyMemory(addr uint32, expected []byte) error {
	b, e := u.readMemory(addr, int64(len(expected)), fmt.Sprintf("readback-%x.bin", addr))
	if e != nil {
		return e
	}
	if !bytes.Equal(b, expected) {
		return fmt.Errorf("RAM readback mismatch; загрузка запрещена")
	}
	return nil
}

func (u *USB) Console(operation, folder, nonce string, timeout time.Duration) (string, error) {
	commands := map[string]string{"scan": "/capsula-nand-agent scan", "metadata": "/capsula-nand-agent metadata", "stock": "/capsula-inspect-stock", "inspect": "/capsula-inspect-device", "credentials": "/capsula-inspect-device credentials", "restart-check": "/capsula-ram-restart check", "restart": "/capsula-ram-restart schedule", "probe": "/capsula-control probe", "probe-check": "/capsula-control probe-check", "install": "/capsula-control install", "refresh": "/capsula-control refresh", "rollback": "/capsula-control rollback"}
	command, ok := commands[operation]
	if !ok || !digestRE.MatchString(nonce) {
		return "", fmt.Errorf("неверная операция/nonce RAM")
	}
	begin, end := "CAPSULA_BEGIN_"+nonce, "CAPSULA_END_"+nonce
	line := fmt.Sprintf("printf '\\n%s\\n'; test \"$(/bin/busybox cat /capsula-run-id)\" = %s && %s; rc=$?; printf '\\n%s:%%s\\n' \"$rc\"\n", begin, nonce, command, end)
	var output bytes.Buffer
	e := u.exchangeConsole(line, end, &output, timeout)
	if le := os.WriteFile(filepath.Join(folder, "console-"+operation+".txt"), output.Bytes(), 0600); le != nil {
		return "", le
	}
	if e != nil {
		return "", fmt.Errorf("RAM %s: %w; частичный журнал сохранён", operation, e)
	}
	body := strings.ReplaceAll(output.String(), "\r", "")
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(begin) + `\n(.*?)^` + regexp.QuoteMeta(end) + `:([0-9]+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("неполный ответ RAM")
	}
	if m[2] != "0" {
		reason := ""
		for _, line := range strings.Split(m[1], "\n") {
			if strings.HasPrefix(line, "REFUSED:") {
				runes := []rune(strings.Map(func(r rune) rune {
					if r < 32 || r == 127 {
						return -1
					}
					return r
				}, line))
				if len(runes) > 320 {
					runes = runes[:320]
				}
				reason = "; " + string(runes)
				break
			}
		}
		return "", fmt.Errorf("RAM %s отказал (код %s)%s; журнал %s; автоматического повтора записи нет", operation, m[2], reason, folder)
	}
	return m[1], nil
}
