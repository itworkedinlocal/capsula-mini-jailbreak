package capsula

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// INPUT_RECORD with its KEY_EVENT_RECORD union, per the Windows console ABI.
type consoleKeyRecord struct {
	kind, padding           uint16
	down                    int32
	repeat, key, scan, char uint16
	control                 uint32
}

func injectConsoleKeys(input *os.File, text string) error {
	var records []consoleKeyRecord
	for _, char := range utf16.Encode([]rune(text)) {
		key := uint16(0)
		if char == '\r' {
			key = 13
		}
		records = append(records, consoleKeyRecord{kind: 1, down: 1, repeat: 1, key: key, char: char})
	}
	var written uint32
	err := boolCall(windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteConsoleInputW"), input.Fd(), uintptr(unsafe.Pointer(&records[0])), uintptr(len(records)), uintptr(unsafe.Pointer(&written)))
	runtime.KeepAlive(records)
	if err != nil {
		return err
	}
	if int(written) != len(records) {
		return fmt.Errorf("incomplete console input")
	}
	return nil
}

type consolePromptWriter struct {
	bytes.Buffer
	input   *os.File
	choices []string
	err     error
}

func (w *consolePromptWriter) Write(p []byte) (int, error) {
	text := string(p)
	choice := ""
	switch {
	case strings.Contains(text, "Выберите пункт:"):
		if len(w.choices) == 0 {
			w.err = fmt.Errorf("unexpected menu prompt")
		} else {
			choice = w.choices[0]
			w.choices = w.choices[1:]
		}
	case strings.Contains(text, "[y/N]:"):
		if len(w.choices) == 0 {
			w.err = fmt.Errorf("unexpected confirmation prompt")
		} else {
			choice = w.choices[0]
			w.choices = w.choices[1:]
		}
	case strings.Contains(text, "Пароль root"), strings.Contains(text, "Повторите пароль"):
		choice = "тест7\r"
	}
	if choice != "" && w.err == nil {
		w.err = injectConsoleKeys(w.input, choice)
	}
	return w.Buffer.Write(p)
}

func TestWindowsRealConsoleMenuPasswordAndExplorerPause(t *testing.T) {
	if os.Getenv("CAPSULA_CONSOLE_TEST_CHILD") != "1" {
		// An isolated hidden console, never the owner's console. Relocation also
		// guarantees Run's error scenario cannot find resources or access USB.
		folder := t.TempDir()
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(folder, "console-test.exe")
		if err = os.WriteFile(child, content, 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, child, "-test.run=^TestWindowsRealConsoleMenuPasswordAndExplorerPause$", "-test.v")
		cmd.Dir = folder
		cmd.Env = append(os.Environ(), "CAPSULA_CONSOLE_TEST_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
		body, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated console: %v: %s", err, body)
		}
		if !bytes.Contains(body, []byte("Нажмите Enter, чтобы закрыть окно.")) || !bytes.Contains(body, []byte("не найден комплект ресурсов")) {
			t.Fatalf("error/pause not exercised: %s", body)
		}
		return
	}
	if unsafe.Sizeof(consoleKeyRecord{}) != 20 {
		t.Fatal("invalid console record ABI")
	}
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	oldInput, oldArgs := os.Stdin, os.Args
	os.Stdin = input
	defer func() { os.Stdin = oldInput; os.Args = oldArgs }()
	_, _, _ = platformEntry() // the application's real UTF-8 console initialization
	writer := &consolePromptWriter{input: input, choices: []string{"5\r", "0\r", "0\r", "\r", "y\r"}}
	terminal := &Terminal{Input: input, Output: writer, Reader: bufio.NewReader(input)}
	if !terminal.Interactive() {
		t.Fatal("fixture is not a real console")
	}
	command, _, err := terminal.Menu()
	if err != nil || command != "" {
		t.Fatal(command, err)
	}
	if yes, e := terminal.Confirm("default-no"); e != nil || yes {
		t.Fatal(yes, e)
	}
	if yes, e := terminal.Confirm("explicit-yes"); e != nil || !yes {
		t.Fatal(yes, e)
	}
	var before, after uint32
	if err = windows.GetConsoleMode(windows.Handle(input.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	password, err := terminal.Password(true)
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "тест7" {
		clear(password)
		t.Fatal("Unicode password changed")
	}
	clear(password)
	if err = windows.GetConsoleMode(windows.Handle(input.Fd()), &after); err != nil || after != before {
		t.Fatal("password did not restore console mode", before, after, err)
	}
	if writer.err != nil || len(writer.choices) != 0 {
		t.Fatal(writer.err, writer.choices)
	}
	screen, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer screen.Close()
	cells := make([]uint16, 2000)
	var n uint32
	if err = boolCall(windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleOutputCharacterW"), screen.Fd(), uintptr(unsafe.Pointer(&cells[0])), uintptr(len(cells)), 0, uintptr(unsafe.Pointer(&n))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(utf16.Decode(cells[:n])), "тест7") {
		t.Fatal("password echoed to real console")
	}
	// Actual Run, as after an Explorer double click: menu -> diagnose -> missing
	// resources -> error. It must stay alive until a fresh Enter is supplied.
	os.Args = []string{oldArgs[0]}
	if err = injectConsoleKeys(input, "5\r1\r"); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() { done <- Run() }()
	select {
	case code := <-done:
		t.Fatal("window returned before Enter", code)
	case <-time.After(300 * time.Millisecond):
	}
	if err = injectConsoleKeys(input, "\r"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 1 {
			t.Fatal("expected missing-resources error", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("window did not finish after Enter")
	}
}
