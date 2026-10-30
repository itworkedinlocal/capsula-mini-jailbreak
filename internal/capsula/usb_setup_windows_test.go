package capsula

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type testUSBInstaller struct {
	calls  atomic.Int32
	closed atomic.Bool
	action func(context.Context, usbSetupDevice) error
}

func (d *testUSBInstaller) close() { d.closed.Store(true) }
func (d *testUSBInstaller) install(ctx context.Context, target usbSetupDevice) error {
	d.calls.Add(1)
	if d.action != nil {
		return d.action(ctx, target)
	}
	return nil
}

// Uses the production pipe protocol and helper state machine, but no driver
// mutation. SetupAPI snapshots in the helper are read-only.
func testSetupSession(t *testing.T, driver *testUSBInstaller, prepareErr error) (*usbSetupSession, <-chan int) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	runID := SHA([]byte(t.TempDir()))
	pipe, err := createSetupPipe(runID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getpid()))
	if err != nil {
		cancel()
		windows.CloseHandle(pipe)
		t.Fatal(err)
	}
	s := &usbSetupSession{pipe: pipe, process: process, runID: runID, ctx: ctx, cancel: cancel}
	t.Cleanup(func() {
		// The test peer is this process, not a child we can wait for.
		if s.process != 0 {
			windows.CloseHandle(s.process)
			s.process = 0
		}
		s.close()
	})
	peerCtx, peerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(peerCancel)
	done := make(chan int, 1)
	go func() {
		client, e := openSetupClient(runID, uint32(os.Getpid()))
		if e != nil {
			done <- -1
			return
		}
		defer windows.CloseHandle(client)
		done <- serveUSBSetup(peerCtx, client, runID, func() (usbDriverInstaller, error) { return driver, prepareErr })
	}()
	if err = connectSetupPipe(ctx, pipe); err != nil {
		t.Fatal(err)
	}
	return s, done
}

func TestWindowsSetupPreparedBeforeTargetAndReceipt(t *testing.T) {
	driver := &testUSBInstaller{}
	s, done := testSetupSession(t, driver, nil)
	report, err := s.receive(s.ctx)
	if err != nil || report.Phase != "prepared" || report.Installed || driver.calls.Load() != 0 {
		t.Fatal(report, err, driver.calls.Load())
	}
	target := setupTestDevice()
	report, err = s.install(s.ctx, target)
	if err != nil || report.validateInstallation(s.runID, target) != nil || report.Passed || driver.calls.Load() != 1 {
		t.Fatal(report, err, driver.calls.Load())
	}
	if err = report.validate(s.runID, target); err == nil {
		t.Fatal("installation marked USB ready without transfers")
	}
	if code := <-done; code != 0 || !driver.closed.Load() {
		t.Fatal(code, driver.closed.Load())
	}
}

func TestWindowsSetupCancellationBeforeTargetAndDuringInstall(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-target", true: "during-install"}[during], func(t *testing.T) {
			started := make(chan struct{})
			driver := &testUSBInstaller{action: func(ctx context.Context, _ usbSetupDevice) error { close(started); <-ctx.Done(); return ctx.Err() }}
			s, done := testSetupSession(t, driver, nil)
			if _, err := s.receive(s.ctx); err != nil {
				t.Fatal(err)
			}
			if during {
				result := make(chan error, 1)
				go func() { _, err := s.install(s.ctx, setupTestDevice()); result <- err }()
				<-started
				s.cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else {
				s.cancel()
			}
			// Closing the parent channel also cancels an independently elevated peer.
			windows.DisconnectNamedPipe(s.pipe)
			select {
			case code := <-done:
				if code == 0 {
					t.Fatal("cancelled setup succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("helper did not exit on cancellation")
			}
			if !during && driver.calls.Load() != 0 {
				t.Fatal("driver changed before target")
			}
		})
	}
}

func TestWindowsSetupPreparationFailureIsReported(t *testing.T) {
	s, done := testSetupSession(t, &testUSBInstaller{}, errors.New("inbox fixture missing"))
	_, err := s.receive(s.ctx)
	if err == nil || !strings.Contains(err.Error(), "prepare-system-winusb") {
		t.Fatal(err)
	}
	if code := <-done; code != 1 {
		t.Fatal(code)
	}
}

func TestWindowsSetupRejectsInvalidCommands(t *testing.T) {
	for _, kind := range []string{"stale-run", "other-operation", "invalid-target", "expired"} {
		t.Run(kind, func(t *testing.T) {
			driver := &testUSBInstaller{}
			s, done := testSetupSession(t, driver, nil)
			if _, err := s.receive(s.ctx); err != nil {
				t.Fatal(err)
			}
			command := usbSetupCommand{Operation: "usb-driver-setup", RunID: s.runID, Phase: "install", Target: setupTestDevice(), Deadline: time.Now().Add(time.Second)}
			switch kind {
			case "stale-run":
				command.RunID = strings.Repeat("f", 64)
			case "other-operation":
				command.Operation = "other"
			case "invalid-target":
				command.Target.ID = "USB\\OTHER\\x"
			case "expired":
				command.Deadline = time.Now().Add(-time.Second)
			}
			if err := writeSetupJSON(s.ctx, s.pipe, command); err != nil {
				t.Fatal(err)
			}
			if code := <-done; code != 1 || driver.calls.Load() != 0 {
				t.Fatal(code, driver.calls.Load())
			}
		})
	}
}

func TestWindowsSetupPipeCancellationAndPeerIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pipe, err := createSetupPipe(SHA([]byte(t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	cancel()
	if err = connectSetupPipe(ctx, pipe); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	runID := SHA([]byte(t.TempDir()))
	another, err := createSetupPipe(runID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(another)
	if h, e := openSetupClient(runID, uint32(os.Getpid()+1)); e == nil {
		windows.CloseHandle(h)
		t.Fatal("wrong parent PID accepted")
	}
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), "..\\other"} {
		if _, err := setupPipeName(invalid); err == nil {
			t.Fatal("unsafe pipe ID accepted")
		}
	}
}

func TestWindowsUSBEnumerationReadOnly(t *testing.T) {
	nodes, err := loaderSetupSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if err = node.validate(); err != nil {
			t.Fatal(err)
		}
		t.Logf("present USB loader: instance=%s path=%s service=%s status=%#x problem=%d", node.ID, node.Location, node.Service, node.Status, node.Problem)
	}
	configured, err := configuredLoaderTargets()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range configured {
		if err = node.validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func testWindowsWaitUSB(t *testing.T) (*USB, *windowsUSBOperations, windowsUSBNode, *[]string) {
	t.Helper()
	target := setupTestDevice()
	node := windowsUSBNode{id: target.ID, location: target.Location, service: "WinUSB"}
	messages := []string{}
	u := &USB{ctx: context.Background(), notify: func(s string) { messages = append(messages, s) }}
	ops := u.windowsOperations()
	ops.enumerate = func() ([]windowsUSBNode, error) { return []windowsUSBNode{node}, nil }
	ops.configured = func() ([]usbSetupDevice, error) { return []usbSetupDevice{target}, nil }
	ops.interfacePath = func(string) (string, error) { return "test-interface", nil }
	ops.open = func(string) (*winUSBWire, error) { return &winUSBWire{}, nil }
	ops.verify = func() error { return nil }
	ops.prepare = func(context.Context) (*usbSetupSession, error) {
		t.Error("unexpected UAC/driver reinstallation")
		return nil, errors.New("unexpected UAC")
	}
	t.Cleanup(u.Close)
	return u, ops, node, &messages
}

func TestWindowsConfiguredWaitRetriesWithoutSetup(t *testing.T) {
	u, ops, _, messages := testWindowsWaitUSB(t)
	calls := 0
	ops.interfacePath = func(string) (string, error) {
		calls++
		if calls < 4 {
			return "", windows.ERROR_FILE_NOT_FOUND
		}
		return "test-interface", nil
	}
	if err := u.Prepare(u.notify); err != nil {
		t.Fatal(err)
	}
	if err := u.Wait(time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 4 || len(*messages) != 1 || u.platform.setupAttempted {
		t.Fatal(calls, *messages, u.platform.setupAttempted)
	}
	// A subsequent RAM->loader cycle must not ask for UAC or reconnect.
	if err := u.Wait(time.Second); err != nil {
		t.Fatal(err)
	}
	if len(*messages) != 2 {
		t.Fatal(*messages)
	}
}

func TestWindowsConfiguredWaitAccessErrorsDoNotInstall(t *testing.T) {
	for _, want := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION} {
		t.Run(want.Error(), func(t *testing.T) {
			u, ops, _, _ := testWindowsWaitUSB(t)
			ops.open = func(string) (*winUSBWire, error) { return nil, want }
			if err := u.Wait(time.Second); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if u.platform.setupAttempted {
				t.Fatal("access error caused reinstall")
			}
		})
	}
}

func TestWindowsWaitRejectsChangedTargetAndVerificationFailure(t *testing.T) {
	for _, kind := range []string{"different", "multiple", "bad-ram"} {
		t.Run(kind, func(t *testing.T) {
			u, ops, node, _ := testWindowsWaitUSB(t)
			if kind == "bad-ram" {
				ops.verify = func() error { return errors.New("RAM mismatch") }
				if err := u.Wait(time.Second); err == nil || !strings.Contains(err.Error(), "RAM mismatch") {
					t.Fatal(err)
				}
				if u.platform.wire != nil {
					t.Fatal("failed verification kept open channel")
				}
				return
			}
			calls := 0
			ops.interfacePath = func(string) (string, error) { return "", windows.ERROR_FILE_NOT_FOUND }
			ops.enumerate = func() ([]windowsUSBNode, error) {
				calls++
				if calls > 2 {
					if kind == "multiple" {
						return []windowsUSBNode{node, node}, nil
					}
					node.id += "-OTHER"
				}
				return []windowsUSBNode{node}, nil
			}
			if err := u.Wait(time.Second); err == nil {
				t.Fatal("device substitution accepted")
			}
		})
	}
}

func TestWindowsReconnectPromptIsExplicitAndOnce(t *testing.T) {
	u, _, _, messages := testWindowsWaitUSB(t)
	for n := 0; n < 3; n++ {
		u.requestSetupReconnect()
	}
	if len(*messages) != 1 || !strings.Contains((*messages)[0], "Сейчас переподключите") || !strings.Contains((*messages)[0], "10 секунд") || !strings.Contains((*messages)[0], "тот же разъём") {
		t.Fatal(*messages)
	}
}

func TestWindowsDriverPreparationReadOnly(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("system driver list preparation requires an elevated test token")
	}
	driver, err := prepareLoaderDriver()
	if err != nil {
		t.Fatal(err)
	}
	driver.close()
}

func TestWindowsFirstSetupCompletesAfterOneExplicitReconnect(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	u, ops, node, messages := testWindowsWaitUSB(t)
	node.service = "vendor"
	ops.configured = func() ([]usbSetupDevice, error) { return nil, nil }
	var installed, reconnected atomic.Bool
	var prepared bool
	ops.enumerate = func() ([]windowsUSBNode, error) {
		if !prepared {
			return nil, nil
		}
		current := node
		if installed.Load() {
			if !reconnected.Load() {
				return nil, nil
			}
			current.service = "WinUSB"
		}
		return []windowsUSBNode{current}, nil
	}
	driver := &testUSBInstaller{action: func(context.Context, usbSetupDevice) error { installed.Store(true); return nil }}
	ops.prepare = func(context.Context) (*usbSetupSession, error) {
		s, _ := testSetupSession(t, driver, nil)
		if report, err := s.receive(s.ctx); err != nil || report.Phase != "prepared" {
			t.Fatal(report, err)
		}
		prepared = true
		return s, nil
	}
	u.notify = func(message string) {
		*messages = append(*messages, message)
		if strings.Contains(message, "Сейчас переподключите") {
			reconnected.Store(true)
		}
	}
	if err := u.Prepare(u.notify); err != nil {
		t.Fatal(err)
	}
	if driver.calls.Load() != 0 {
		t.Fatal("installed before initial connection")
	}
	if err := u.Wait(4 * time.Second); err != nil {
		t.Fatal(err, *messages)
	}
	if driver.calls.Load() != 1 || !reconnected.Load() || u.platform.setupReport != nil {
		t.Fatal(driver.calls.Load(), reconnected.Load(), u.platform.setupReport)
	}
	prompts := 0
	for _, message := range *messages {
		if strings.Contains(message, "Сейчас переподключите") {
			prompts++
		}
	}
	if prompts != 1 {
		t.Fatal(*messages)
	}
	if err := u.Wait(time.Second); err != nil {
		t.Fatal(err)
	}
	if driver.calls.Load() != 1 {
		t.Fatal("reinstalled on automatic RAM restart")
	}
}

func TestWindowsSetupRejectsStaleResponseAndInvalidProcess(t *testing.T) {
	for _, kind := range []string{"stale-run", "invalid-process"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			runID := SHA([]byte(t.TempDir()))
			pipe, err := createSetupPipe(runID)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(pipe)
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(process)
			if kind == "invalid-process" {
				process = 0
			} // an invalid process handle must fail PID verification
			s := &usbSetupSession{pipe: pipe, process: process, runID: runID, ctx: ctx, cancel: cancel}
			done := make(chan error, 1)
			go func() {
				h, e := openSetupClient(runID, uint32(os.Getpid()))
				if e != nil {
					done <- e
					return
				}
				defer windows.CloseHandle(h)
				report := usbSetupReport{Operation: "usb-driver-setup", RunID: strings.Repeat("0", 64), Phase: "prepared"}
				if kind == "invalid-process" {
					report.RunID = runID
				}
				done <- writeSetupJSON(ctx, h, report)
			}()
			if err = connectSetupPipe(ctx, pipe); err != nil {
				t.Fatal(err)
			}
			if _, err = s.receive(ctx); err == nil {
				t.Fatal("untrusted report accepted")
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
