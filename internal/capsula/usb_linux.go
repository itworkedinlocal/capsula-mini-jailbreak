package capsula

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type usbPlatform struct{}

func usbNotice(message string) { fmt.Println(message) }

func (u *USB) closePlatform()         {}
func (u *USB) closeSetup()            {}
func (u *USB) preparePlatform() error { return nil }

func (u *USB) RAMAvailable() bool {
	target, e := filepath.EvalSymlinks("/dev/capsula-ram-console")
	if e != nil {
		return false
	}
	i, e := os.Stat(target)
	return e == nil && i.Mode()&os.ModeCharDevice != 0
}

func NewUSB(ctx context.Context, r Resources, folder string) (*USB, error) {
	if os.Geteuid() == 0 {
		return nil, fmt.Errorf("запускайте обычным пользователем; доступ к USB через udev")
	}
	if e := r.Check(); e != nil {
		return nil, e
	}
	release, e := lockFile(fmt.Sprintf("/tmp/capsula-a113x-usb-%d.lock", os.Getuid()))
	if e != nil {
		return nil, e
	}
	u := &USB{r: r, folder: folder, ctx: ctx, release: release, memory: map[uint32][]byte{}, bulk: map[string]bool{"echo priming": true, "env export -t 0x2000000": true}, stores: map[string]int64{}}
	return u, nil
}
func (u *USB) call(a []string, launch bool) ([]byte, error) {
	if e := u.validate(a); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(u.ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(u.r.Root, "update"), a...)
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "LD_LIBRARY_PATH=") {
			env = append(env, v)
		}
	}
	cmd.Env = append(env, "LD_LIBRARY_PATH="+u.r.Stock("bin/x86_64"))
	start := time.Now()
	body, e := cmd.CombinedOutput()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	row := map[string]any{"argv": a, "seconds": time.Since(start).Seconds(), "returncode": code, "output": string(body)}
	f, le := os.OpenFile(filepath.Join(u.folder, "usb-commands.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if le != nil {
		return nil, le
	}
	le = json.NewEncoder(f).Encode(row)
	f.Close()
	if le != nil {
		return nil, le
	}
	if ctx.Err() != nil {
		if launch && ctx.Err() == context.DeadlineExceeded {
			return body, nil
		}
		return body, fmt.Errorf("USB command timeout/interrupted: %w", ctx.Err())
	}
	if e != nil {
		var exit *exec.ExitError
		if !errors.As(e, &exit) {
			return body, e
		}
		if status, ok := exit.Sys().(unix.WaitStatus); ok && status.Signaled() {
			return body, e
		}
	}
	lower := strings.ToLower(string(body))
	expectedPrime := len(a) == 2 && a[0] == "bulkcmd" && a[1] == "echo priming" && strings.TrimSpace(lower) == "amlusbbulkcmd[echo priming]\n[amlusbrom]err:bulkinreply=[failed:]\nerr: amlusbbulkcmd failed!"
	if !launch && !expectedPrime && (strings.Contains(lower, "err:") || strings.Contains(lower, "[info]failed")) {
		return body, fmt.Errorf("USB helper сообщил ошибку; журнал %s", u.folder)
	}
	return body, nil
}
func loaderNodes() ([]string, error) {
	entries, e := os.ReadDir("/sys/bus/usb/devices")
	if e != nil {
		return nil, e
	}
	var nodes []string
	for _, entry := range entries {
		p := filepath.Join("/sys/bus/usb/devices", entry.Name())
		read := func(n string) string { b, _ := os.ReadFile(filepath.Join(p, n)); return strings.TrimSpace(string(b)) }
		if read("idVendor") != "1b8e" || read("idProduct") != "c003" {
			continue
		}
		bus, e := strconv.Atoi(read("busnum"))
		if e != nil {
			continue
		}
		number, e := strconv.Atoi(read("devnum"))
		if e != nil {
			continue
		}
		node := fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, number)
		i, e := os.Stat(node)
		if e == nil && i.Mode()&os.ModeCharDevice != 0 {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}
func (u *USB) Wait(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	denied := false
	for time.Now().Before(deadline) {
		nodes, e := loaderNodes()
		if e != nil {
			return e
		}
		if len(nodes) > 1 {
			return fmt.Errorf("обнаружено несколько загрузчиков; оставьте одну Капсулу")
		}
		if len(nodes) == 0 || unix.Access(nodes[0], unix.R_OK|unix.W_OK) != nil {
			denied = denied || len(nodes) > 0
			if e = waitContext(u.ctx, 20*time.Millisecond); e != nil {
				return e
			}
			continue
		}
		body, e := u.call([]string{"identify", "7"}, false)
		if e == nil && bytes.Contains(bytes.ToLower(body), []byte("firmware version")) && bytes.Contains(body, []byte("0-7-0-16-0-0-0")) {
			if e = waitContext(u.ctx, 500*time.Millisecond); e != nil {
				return e
			}
			for i := 0; i < 2; i++ {
				if _, e = u.call([]string{"bulkcmd", "echo priming"}, false); e != nil {
					return e
				}
			}
			a, e := u.readMemory(0x4000000, 2048, "channel-0.bin")
			if e != nil {
				return e
			}
			b, e := u.readMemory(0x4000000, 2048, "channel-1.bin")
			if e != nil {
				return e
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("два чтения RAM не совпали; запись не начата")
			}
			return nil
		}
		if e = waitContext(u.ctx, 20*time.Millisecond); e != nil {
			return e
		}
	}
	if denied {
		return fmt.Errorf("загрузчик появлялся, но недоступен; проверьте udev/ACL и полностью отключите питание")
	}
	return fmt.Errorf("%w: загрузчик A113X не найден; полностью отключите питание и повторите подключение", ErrLoaderTimeout)
}
func pollFD(ctx context.Context, fd int, event int16, deadline time.Time) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		left := time.Until(deadline)
		if left <= 0 {
			return context.DeadlineExceeded
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: event}}
		_, e := unix.Poll(fds, int(min(left.Milliseconds()+1, 200)))
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if fds[0].Revents&event != 0 {
			return nil
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return io.EOF
		}
	}
}
func consoleWrite(ctx context.Context, fd int, data []byte, deadline time.Time) error {
	for len(data) > 0 {
		if e := pollFD(ctx, fd, unix.POLLOUT, deadline); e != nil {
			return e
		}
		n, e := unix.Write(fd, data)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func consoleExchange(ctx context.Context, fd int, line, end string, output *bytes.Buffer, timeout time.Duration) error {
	if e := consoleWrite(ctx, fd, []byte("\x03\n"), time.Now().Add(10*time.Second)); e != nil {
		return e
	}
	if e := waitContext(ctx, 500*time.Millisecond); e != nil {
		return e
	}
	buf := make([]byte, 65536)
	for {
		n, e := unix.Read(fd, buf)
		if e == unix.EAGAIN {
			break
		}
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.EOF
		}
	}
	if e := consoleWrite(ctx, fd, []byte(line), time.Now().Add(10*time.Second)); e != nil {
		return e
	}
	deadline := time.Now().Add(timeout)
	ending := regexp.MustCompile("\\n" + regexp.QuoteMeta(end) + `:[0-9]+\r?\n`)
	for {
		if e := pollFD(ctx, fd, unix.POLLIN, deadline); e != nil {
			return e
		}
		n, e := unix.Read(fd, buf)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.EOF
		}
		if output.Len()+n > 8<<20 {
			return fmt.Errorf("слишком большой ответ RAM")
		}
		output.Write(buf[:n])
		if ending.Match(output.Bytes()) {
			return nil
		}
	}
}
func (u *USB) exchangeConsole(line, end string, output *bytes.Buffer, timeout time.Duration) error {
	deadline := time.Now().Add(60 * time.Second)
	port := "/dev/capsula-ram-console"
	for !Exists(port) {
		if time.Now().After(deadline) {
			return fmt.Errorf("RAM-консоль не появилась")
		}
		if e := waitContext(u.ctx, 200*time.Millisecond); e != nil {
			return e
		}
	}
	target, e := filepath.EvalSymlinks(port)
	if e != nil {
		return e
	}
	if !regexp.MustCompile(`^ttyACM[0-9]+$`).MatchString(filepath.Base(target)) {
		return fmt.Errorf("неожиданная RAM-консоль")
	}
	node, e := filepath.EvalSymlinks(filepath.Join("/sys/class/tty", filepath.Base(target), "device"))
	if e != nil {
		return e
	}
	for !Exists(filepath.Join(node, "idVendor")) {
		parent := filepath.Dir(node)
		if parent == node {
			return fmt.Errorf("нет USB identity консоли")
		}
		node = parent
	}
	for key, want := range map[string]string{"idVendor": "1d6b", "idProduct": "0104", "serial": "capsula-ramboot"} {
		b, e := os.ReadFile(filepath.Join(node, key))
		if e != nil || strings.TrimSpace(string(b)) != want {
			return fmt.Errorf("RAM-консоль принадлежит другому устройству")
		}
	}
	fd, e := unix.Open(target, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	attrs, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return e
	}
	attrs.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	attrs.Oflag &^= unix.OPOST
	attrs.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	attrs.Cflag &^= unix.CSIZE | unix.PARENB | unix.HUPCL
	attrs.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD
	attrs.Cc[unix.VMIN] = 1
	attrs.Cc[unix.VTIME] = 0
	if e = unix.IoctlSetTermios(fd, unix.TCSETS, attrs); e != nil {
		return e
	}
	return consoleExchange(u.ctx, fd, line, end, output, timeout)
}
