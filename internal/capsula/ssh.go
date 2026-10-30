package capsula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func RandomHex(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func ValidatePassword(b []byte) error {
	if len(b) == 0 || len(b) > 512 || !utf8.Valid(b) || bytes.ContainsAny(b, "\x00\r\n") {
		return fmt.Errorf("нужен непустой пароль до 512 байт UTF-8 без NUL/CR/LF")
	}
	return nil
}

type SSHReport struct {
	Root   bool                `json:"ssh_root_verified"`
	Full   bool                `json:"ssh_full_verified"`
	Level  string              `json:"level"`
	Host   string              `json:"host"`
	Stages map[string]SSHStage `json:"stages"`
	Error  string              `json:"error,omitempty"`
}
type SSHStage struct {
	Status  string  `json:"status"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
}
type SSHClient struct {
	client  *ssh.Client
	work    string
	ctx     context.Context
	cancel  context.CancelFunc
	Timeout time.Duration
}
type cappedBuffer struct {
	sync.Mutex
	b   bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.b.Len()+len(p) > b.max {
		return 0, fmt.Errorf("слишком большой вывод SSH")
	}
	return b.b.Write(p)
}
func (b *cappedBuffer) Bytes() []byte { b.Lock(); defer b.Unlock(); return bytes.Clone(b.b.Bytes()) }
func dialSSH(ctx context.Context, host string, port int, key string, password []byte, work string) (*SSHClient, error) {
	if host == "" || strings.ContainsAny(host, "\x00\r\n\t /@") || len(host) > 253 || port < 1 || port > 65535 {
		return nil, fmt.Errorf("некорректный адрес или порт SSH")
	}
	if e := ValidatePassword(password); e != nil {
		return nil, e
	}
	public, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(key))
	if e != nil || len(bytes.TrimSpace(rest)) != 0 || public.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("повреждён сохранённый host key")
	}
	cfg := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(string(password))}, HostKeyCallback: ssh.FixedHostKey(public), Timeout: 10 * time.Second}
	c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if e != nil {
		return nil, fmt.Errorf("адрес/TCP: %w", e)
	}
	if e = c.SetDeadline(time.Now().Add(10 * time.Second)); e != nil {
		c.Close()
		return nil, e
	}
	connection, ch, requests, e := ssh.NewClientConn(c, net.JoinHostPort(host, fmt.Sprint(port)), cfg)
	if e != nil {
		c.Close()
		return nil, fmt.Errorf("SSH handshake/host key/пароль: %w", e)
	}
	c.SetDeadline(time.Time{})
	child, cancel := context.WithCancel(ctx)
	client := &SSHClient{ssh.NewClient(connection, ch, requests), work, child, cancel, 30 * time.Second}
	go func() { <-child.Done(); client.client.Close() }()
	return client, nil
}
func (c *SSHClient) Close() { c.cancel(); c.client.Close() }
func (c *SSHClient) Run(command string, tty bool) ([]byte, error) {
	s, e := c.client.NewSession()
	if e != nil {
		return nil, e
	}
	defer s.Close()
	out, errout := &cappedBuffer{max: 4 << 20}, &cappedBuffer{max: 1 << 20}
	s.Stdout = out
	s.Stderr = errout
	s.Stdin = bytes.NewReader(nil)
	if tty {
		if e = s.RequestPty("dumb", 30, 110, ssh.TerminalModes{ssh.ECHO: 0}); e != nil {
			return nil, e
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(command) }()
	completed := false
	select {
	case e = <-done:
		completed = true
	case <-time.After(c.Timeout):
		s.Close()
		e = fmt.Errorf("превышено время ожидания SSH-команды")
	case <-c.ctx.Done():
		s.Close()
		e = c.ctx.Err()
	}
	// Session.Run joins output copy goroutines; a timeout closes the session,
	// then joins the worker before touching buffers or returning.
	if !completed {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	if len(errout.Bytes()) > 0 {
		_ = os.WriteFile(filepath.Join(c.work, "ssh-stderr.log"), errout.Bytes(), 0600)
	}
	if e != nil {
		detail := strings.TrimSpace(string(errout.Bytes()))
		if len(detail) > 1024 {
			detail = detail[:1024]
		}
		return out.Bytes(), fmt.Errorf("команда %q: %w; stderr: %s", command, e, detail)
	}
	return out.Bytes(), nil
}

func VerifySSH(ctx context.Context, host string, port int, key string, password []byte, work, level string, m *Manifest) (report SSHReport, err error) {
	report = SSHReport{Host: host, Level: level, Stages: map[string]SSHStage{}}
	defer func() {
		if err != nil {
			report.Error = err.Error()
		}
		_ = AtomicJSON(filepath.Join(work, "result.json"), report)
	}()
	var c *SSHClient
	stage := func(name string, fn func() error) error {
		start := time.Now()
		var timer *time.Timer
		if c != nil {
			client := c
			timer = time.AfterFunc(90*time.Second, func() { client.Close() })
		}
		e := fn()
		if timer != nil {
			timer.Stop()
		}
		r := SSHStage{Status: "passed", Seconds: time.Since(start).Seconds()}
		if e != nil {
			r.Status = "failed"
			r.Error = e.Error()
		}
		report.Stages[name] = r
		_ = AtomicJSON(filepath.Join(work, "result.json"), report)
		if e != nil {
			return fmt.Errorf("%s: %w", name, e)
		}
		return nil
	}
	if err = stage("connect", func() error { var e error; c, e = dialSSH(ctx, host, port, key, password, work); return e }); err != nil {
		return
	}
	defer c.Close()
	if err = stage("root", func() error {
		out, e := c.Run("/usr/lib/capsula-root/supervisor identity", false)
		if e != nil {
			return e
		}
		if string(out) != "0\n0\n" {
			return fmt.Errorf("получено не UID/GID=0")
		}
		return nil
	}); err != nil {
		return
	}
	report.Root = true
	if level == "basic" {
		return
	}
	if level != "full" {
		err = fmt.Errorf("неизвестный уровень SSH")
		return
	}
	if m == nil {
		err = fmt.Errorf("нет индивидуального манифеста для полной проверки")
		return
	}
	if err = stage("noninteractive", func() error {
		for _, probe := range []struct {
			cmd, want string
			tty       bool
		}{{"true", "", false}, {"printf CAPSULA_EXACT", "CAPSULA_EXACT", false}, {"printf CAPSULA_EXACT", "CAPSULA_EXACT", true}, {"/bin/sh -l -c 'printf CAPSULA_EXACT'", "CAPSULA_EXACT", false}, {"/bin/sh -i -c 'printf CAPSULA_EXACT'", "CAPSULA_EXACT", false}} {
			out, e := c.Run(probe.cmd, probe.tty)
			if e != nil {
				return e
			}
			if string(out) != probe.want {
				return fmt.Errorf("посторонний вывод команды %q", probe.cmd)
			}
		}
		return nil
	}); err != nil {
		return
	}
	if err = stage("runtime-architecture", func() error {
		out, e := c.Run("/usr/lib/capsula-root/busybox uname -m", false)
		if e != nil {
			return e
		}
		if string(out) != "aarch64\n" {
			return fmt.Errorf("не подтверждена ARM64")
		}
		return nil
	}); err != nil {
		return
	}
	if err = stage("runtime-kernel", func() error {
		out, e := c.Run("/usr/lib/capsula-root/busybox uname -r", false)
		if e != nil {
			return e
		}
		for _, release := range m.Kernels {
			if string(out) == release+"\n" {
				return nil
			}
		}
		return fmt.Errorf("ядро %q не подтверждено собственным stock", strings.TrimSpace(string(out)))
	}); err != nil {
		return
	}
	if err = stage("runtime-service", func() error {
		out, e := c.Run("/usr/lib/capsula-root/service status", false)
		if e != nil {
			return e
		}
		if string(out) != "running\n" {
			return fmt.Errorf("служба SSH не подтверждена: %q", out)
		}
		return nil
	}); err != nil {
		return
	}
	if err = stage("runtime-overlay", func() error {
		out, e := c.Run("/usr/lib/capsula-root/busybox awk '$2==\"/\"&&$3==\"overlay\"{f=1}END{exit !f}' /proc/mounts", false)
		if e != nil {
			return e
		}
		if len(out) != 0 {
			return fmt.Errorf("посторонний вывод проверки OverlayFS")
		}
		return nil
	}); err != nil {
		return
	}
	if err = stage("owned-files", func() error { return c.VerifyOwned(m) }); err != nil {
		return
	}
	if err = stage("login-resize", c.LoginProbe); err != nil {
		return
	}
	if err = stage("sftp", c.TransferProbe); err != nil {
		return
	}
	report.Full = true
	return
}
func (c *SSHClient) VerifyOwned(m *Manifest) error {
	expected := map[string]string{}
	batch := "set -e"
	var body bytes.Buffer
	flush := func() error {
		out, e := c.Run(batch, false)
		if e == nil {
			body.Write(out)
		}
		batch = "set -e"
		return e
	}
	for _, name := range sortedKeys(m.Files) {
		row := m.Files[name]
		if e := SafePackagePath(name); e != nil {
			return e
		}
		path := "/" + name
		expected[path] = row.SHA
		command := fmt.Sprintf("test -f %s; test ! -L %s; test \"$(/usr/lib/capsula-root/busybox stat -c %%u:%%g:%%a %s)\" = 0:0:%o; /usr/lib/capsula-root/busybox sha256sum %s", path, path, path, row.Mode, path)
		if len(command) > 6900 {
			return fmt.Errorf("слишком длинный путь пакета")
		}
		if len(batch)+len(command)+2 > 7000 {
			if e := flush(); e != nil {
				return e
			}
		}
		batch += "; " + command
	}
	if e := flush(); e != nil {
		return e
	}
	actual := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(body.String()), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !digestRE.MatchString(parts[0]) || actual[parts[1]] != "" {
			return fmt.Errorf("повреждён удалённый inventory")
		}
		actual[parts[1]] = parts[0]
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("неполный inventory")
	}
	for p, h := range expected {
		if actual[p] != h {
			return fmt.Errorf("не совпал установленный файл %s", p)
		}
	}
	return nil
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")

func (c *SSHClient) LoginProbe() error {
	s, e := c.client.NewSession()
	if e != nil {
		return e
	}
	defer s.Close()
	out := &cappedBuffer{max: 2 << 20}
	s.Stdout = out
	s.Stderr = out
	in, e := s.StdinPipe()
	if e != nil {
		return e
	}
	if e = s.RequestPty("xterm-256color", 30, 110, ssh.TerminalModes{ssh.ECHO: 0}); e != nil {
		return e
	}
	if e = s.Shell(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	timer := time.NewTimer(c.Timeout)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	nonce := RandomHex(12)
	sent := false
	for {
		select {
		case e = <-done:
			body := bytes.ReplaceAll(out.Bytes(), []byte("\r"), nil)
			_ = os.WriteFile(filepath.Join(c.work, "login.log"), body, 0600)
			if e != nil {
				return e
			}
			if !sent || !bytes.Contains(body, []byte("\n"+nonce+"\n0\n0\n37 123\n")) {
				return fmt.Errorf("интерактивный root/resize не подтверждён")
			}
			return nil
		case <-ticker.C:
			plain := string(ansiRE.ReplaceAll(out.Bytes(), nil))
			if !sent && strings.Contains(plain, "root@") && strings.Contains(plain, "# ") {
				if e = s.WindowChange(37, 123); e != nil {
					return e
				}
				_, e = io.WriteString(in, "printf '\\n"+nonce+"\\n'; /usr/lib/capsula-root/supervisor identity; /usr/lib/capsula-root/busybox stty size; exit\n")
				if e != nil {
					return e
				}
				sent = true
			}
		case <-timer.C:
			return fmt.Errorf("таймаут интерактивного SSH login/resize")
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
}
func (c *SSHClient) TransferProbe() error {
	s, e := sftp.NewClient(c.client)
	if e != nil {
		return e
	}
	defer s.Close()
	dir := "/tmp/capsula-sftp-" + RandomHex(8)
	if e = s.Mkdir(dir); e != nil {
		return e
	}
	defer s.RemoveDirectory(dir)
	path := dir + "/файл с пробелами.bin"
	f, e := s.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	defer s.Remove(path)
	body := make([]byte, 131071)
	if _, e = rand.Read(body); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(body); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	r, e := s.Open(path)
	if e != nil {
		return e
	}
	defer r.Close()
	copy, e := io.ReadAll(io.LimitReader(r, int64(len(body)+1)))
	if e != nil {
		return e
	}
	if !bytes.Equal(copy, body) {
		return fmt.Errorf("SFTP: содержимое не совпало")
	}
	return nil
}
