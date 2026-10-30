package capsula

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	n, e := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	slave, e := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	master := os.NewFile(uintptr(fd), "pty-master")
	t.Cleanup(func() { master.Close(); slave.Close() })
	return master, slave
}
func TestConsolePTYBackpressureAndSingleCommand(t *testing.T) {
	master, slave := openPTY(t)
	fd := int(slave.Fd())
	if _, e := term.MakeRaw(fd); e != nil {
		t.Fatal(e)
	}
	if e := unix.SetNonblock(fd, true); e != nil {
		t.Fatal(e)
	}
	line := strings.Repeat("x", 65536) + "END-COMMAND\n"
	got := make(chan []byte, 1)
	worker := make(chan error, 1)
	go func() {
		var received bytes.Buffer
		buf := make([]byte, 997)
		for !bytes.HasSuffix(received.Bytes(), []byte("END-COMMAND\n")) {
			n, e := master.Read(buf)
			if e != nil {
				worker <- e
				return
			}
			received.Write(buf[:n])
			time.Sleep(time.Millisecond)
		}
		_, e := master.Write([]byte("\nBEGIN\ncomplete\nDONE:0\n"))
		got <- received.Bytes()
		worker <- e
	}()
	var out bytes.Buffer
	e := consoleExchange(context.Background(), fd, line, "DONE", &out, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-worker; e != nil {
		t.Fatal(e)
	}
	if string(<-got) != "\x03\n"+line {
		t.Fatal("partial command replayed/lost")
	}
	if !bytes.Contains(out.Bytes(), []byte("complete")) {
		t.Fatal("output lost")
	}
}
func TestConsoleWriteDeadlineAndDisconnect(t *testing.T) {
	master, slave := openPTY(t)
	fd := int(slave.Fd())
	if _, e := term.MakeRaw(fd); e != nil {
		t.Fatal(e)
	}
	if e := unix.SetNonblock(fd, true); e != nil {
		t.Fatal(e)
	}
	e := consoleWrite(context.Background(), fd, bytes.Repeat([]byte{'x'}, 1<<20), time.Now().Add(30*time.Millisecond))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("unbounded partial write", e)
	}
	master.Close()
	e = consoleWrite(context.Background(), fd, []byte("next"), time.Now().Add(time.Second))
	if e == nil {
		t.Fatal("disconnect ignored")
	}
}
func TestRiskConfirmationsUseYesNoAndDefaultNo(t *testing.T) {
	for _, mode := range []string{"fast", "expert"} {
		for _, answer := range []string{"\n", "n\n", "N\n", "y\n", "Y\n", "yes\nn\n", "БЕЗ БЭКАПА\nn\n"} {
			t.Run(mode+answer, func(t *testing.T) {
				master, slave := openPTY(t)
				var out bytes.Buffer
				terminal := Terminal{Input: slave, Output: &out, Reader: bufio.NewReader(slave)}
				p, _ := NewPolicy(mode, nil)
				go func() { _, _ = io.WriteString(master, answer) }()
				err := terminal.ConfirmPolicy(p)
				accepted := answer == "y\n" || answer == "Y\n"
				if (err == nil) != accepted {
					t.Fatal(answer, err)
				}
				if !strings.Contains(out.String(), "[y/N]") {
					t.Fatal("missing y/N")
				}
				if mode == "expert" && !strings.Contains(out.String(), "ПОТЕРЯТЬ ВСЕ ДАННЫЕ") {
					t.Fatal("risk warning lost")
				}
			})
		}
	}
}
func TestPasswordCancellationRestoresTTY(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()
	original, e := term.GetState(int(slave.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	terminal := &Terminal{Input: slave, Output: io.Discard, Reader: bufio.NewReader(slave), Ctx: ctx}
	done := make(chan error, 1)
	go func() { _, e := terminal.Password(false); done <- e }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("password cancellation blocked")
	}
	current, e := term.GetState(int(slave.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprint(original) != fmt.Sprint(current) {
		t.Fatal("terminal state was not restored")
	}
	master.Close()
}
func TestModeCLIRejectsAutomaticRiskBypass(t *testing.T) {
	var out bytes.Buffer
	code := Main([]string{"root", "--mode", "expert", "--yes"}, os.Stdin, &out, &out)
	if code != 2 || !strings.Contains(out.String(), "flag provided but not defined") {
		t.Fatal("--yes accepted", code, out.String())
	}
}

func TestMenusThroughRealPTY(t *testing.T) {
	t.Setenv("TERM", "dumb")
	master, slave := openPTY(t)
	var output bytes.Buffer
	terminal := Terminal{Input: slave, Output: &output, Reader: bufio.NewReader(slave)}
	done := make(chan error, 1)
	go func() {
		_, err := master.Write([]byte("5\n0\n4\n1\n"))
		done <- err
	}()
	command, action, err := terminal.Menu()
	if writeErr := <-done; writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil || command != "entware" || action != "status" {
		t.Fatal(command, action, err)
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatal("ANSI in dumb terminal")
	}
	if !strings.Contains(output.String(), "Обслуживание") || !strings.Contains(output.String(), "Назад") {
		t.Fatal("missing submenu")
	}
}

func TestExpertWriteNeedsFreshYesNo(t *testing.T) {
	for _, writeAnswer := range []string{"\n", "n\n", "y\n"} {
		t.Run(writeAnswer, func(t *testing.T) {
			master, slave := openPTY(t)
			var out bytes.Buffer
			terminal := Terminal{Input: slave, Output: &out, Reader: bufio.NewReader(slave)}
			p, _ := NewPolicy("expert", []string{"backup"})
			go func() { _, _ = io.WriteString(master, "y\n"+writeAnswer) }()
			if err := terminal.ConfirmPolicy(p); err != nil {
				t.Fatal(err)
			}
			err := terminal.BeforeWrite(strings.Repeat("a", 64), "install", p)
			if (err == nil) != (writeAnswer == "y\n") {
				t.Fatal("old mode consent reused", err)
			}
			if strings.Count(out.String(), "[y/N]") != 2 {
				t.Fatal("write confirmation missing")
			}
		})
	}
}
