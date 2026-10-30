package capsula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func setupPipeName(runID string) (string, error) {
	if !digestRE.MatchString(runID) {
		return "", fmt.Errorf("неверный идентификатор настройки USB")
	}
	return "\\\\.\\pipe\\Capsula-driver-" + runID, nil
}

func createSetupPipe(runID string) (windows.Handle, error) {
	name, err := setupPipeName(runID)
	if err != nil {
		return 0, err
	}
	me, err := userSID()
	if err != nil {
		return 0, err
	}
	// A different administrator may answer UAC. No secrets cross this pipe.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + me.String() + ")(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(name)
	return windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 32768, 32768, 0, &sa)
}

func connectSetupPipe(ctx context.Context, pipe windows.Handle) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(pipe, &ov)
	if err == windows.ERROR_IO_PENDING {
		waitErr := waitWindowsIO(ctx, pipe, &ov, time.Time{})
		var n uint32
		err = windows.GetOverlappedResult(pipe, &ov, &n, true)
		if waitErr != nil {
			err = waitErr
		}
	}
	if err == windows.ERROR_PIPE_CONNECTED {
		return nil
	}
	return err
}

func writeSetupJSON(ctx context.Context, pipe windows.Handle, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > 32768 {
		return fmt.Errorf("слишком большой ответ настройки USB")
	}
	for len(body) > 0 {
		n, e := commTransfer(ctx, pipe, body, true, time.Time{})
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		body = body[n:]
	}
	return nil
}

func readSetupJSON(ctx context.Context, pipe windows.Handle, value any) error {
	var body []byte
	buffer := make([]byte, 4096)
	for len(body) <= 32768 {
		n, err := commTransfer(ctx, pipe, buffer, false, time.Time{})
		body = append(body, buffer[:n]...)
		if len(body) > 32768 {
			break
		}
		if bytes.Contains(body, []byte{'\n'}) {
			if e := UniqueJSON(body); e != nil {
				return e
			}
			return json.Unmarshal(body, value)
		}
		if err != nil {
			return fmt.Errorf("неполный ответ настройки USB: %w", err)
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return fmt.Errorf("слишком большой ответ настройки USB")
}

func setupAck(ctx context.Context, pipe windows.Handle, write bool) error {
	b := []byte{1}
	n, err := commTransfer(ctx, pipe, b, write, time.Time{})
	if err != nil {
		return err
	}
	if n != 1 || b[0] != 1 {
		return fmt.Errorf("не получено подтверждение настройки USB")
	}
	return nil
}

func openSetupClient(runID string, parentPID uint32) (windows.Handle, error) {
	name, err := setupPipeName(runID)
	if err != nil {
		return 0, err
	}
	p, _ := windows.UTF16PtrFromString(name)
	// Identification level prevents a pipe server impersonating an elevated child.
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return 0, err
	}
	var pid uint32
	if err = windows.GetNamedPipeServerProcessId(h, &pid); err != nil || pid != parentPID {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("канал настройки USB принадлежит другому процессу: %v", err)
	}
	return h, nil
}

func usbSetupEntry(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Настройка USB запускается основной программой")
		return 2
	}
	parentPID, err := strconv.ParseUint(args[1], 10, 32)
	if _, e := setupPipeName(args[0]); e != nil || err != nil || parentPID == 0 {
		return 2
	}
	pipe, err := openSetupClient(args[0], uint32(parentPID))
	if err != nil {
		return 1
	}
	defer windows.CloseHandle(pipe)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(parentPID))
	if err != nil {
		return 1
	}
	defer windows.CloseHandle(parent)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for ctx.Err() == nil {
			state, err := windows.WaitForSingleObject(parent, 100)
			if err != nil || state == windows.WAIT_OBJECT_0 {
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); <-exited }()
	return serveUSBSetup(ctx, pipe, args[0], func() (usbDriverInstaller, error) { return prepareLoaderDriver() })
}

type usbDriverInstaller interface {
	close()
	install(context.Context, usbSetupDevice) error
}

// Both sides use lockstep messages and receipts. In particular the child stays
// connected until its PID and final report have been checked by the parent.
func serveUSBSetup(ctx context.Context, pipe windows.Handle, runID string, prepare func() (usbDriverInstaller, error)) int {
	report := usbSetupReport{Operation: "usb-driver-setup", RunID: runID, Time: Now(), Phase: "prepared"}
	driver, err := prepare()
	if err != nil {
		report.Phase, report.Error = "failed", "prepare-system-winusb: "+err.Error()
	} else {
		defer driver.close()
	}
	if writeSetupJSON(ctx, pipe, report) != nil || setupAck(ctx, pipe, false) != nil || err != nil {
		return 1
	}
	var request usbSetupCommand
	if readSetupJSON(ctx, pipe, &request) != nil {
		return 1
	}
	if request.RunID != runID || request.Operation != report.Operation || request.Phase != "install" || request.Target.validate() != nil || !request.Deadline.After(time.Now()) {
		return 1
	}
	installCtx, stop := context.WithDeadline(ctx, request.Deadline)
	defer stop()
	ack := make(chan error, 1)
	go func() {
		e := setupAck(installCtx, pipe, false)
		if e != nil {
			stop()
		}
		ack <- e
	}()
	ackJoined := false
	defer func() {
		stop()
		if !ackJoined {
			<-ack
		}
	}()
	report.Target, report.Phase = request.Target, "failed"
	report.Before, err = loaderSetupSnapshot()
	if err == nil {
		err = driver.install(installCtx, request.Target)
	}
	report.After, _ = loaderSetupSnapshot()
	report.Time = Now()
	report.Installed = err == nil
	if err == nil {
		report.Phase = "driver-installed"
	} else {
		report.Error = err.Error()
	}
	if writeSetupJSON(installCtx, pipe, report) != nil {
		return 1
	}
	// Wait for the ACK before returning; cancellation also joins the reader.
	select {
	case e := <-ack:
		ackJoined = true
		if e != nil {
			return 1
		}
	case <-installCtx.Done():
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func driverSetupReport() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "Capsula", "driver-setup.json"), nil
}

type usbSetupSession struct {
	pipe    windows.Handle
	process windows.Handle
	runID   string
	ctx     context.Context
	cancel  context.CancelFunc
}

func (s *usbSetupSession) close() {
	if s == nil {
		return
	}
	s.cancel()
	if s.pipe != 0 {
		windows.DisconnectNamedPipe(s.pipe)
		windows.CloseHandle(s.pipe)
		s.pipe = 0
	}
	if s.process != 0 {
		// Closing the channel lets an idle elevated child exit without installing.
		windows.WaitForSingleObject(s.process, 2000)
		windows.CloseHandle(s.process)
		s.process = 0
	}
}

func (s *usbSetupSession) receive(ctx context.Context) (usbSetupReport, error) {
	var report usbSetupReport
	if err := readSetupJSON(ctx, s.pipe, &report); err != nil {
		return report, err
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(s.pipe, &pid); err != nil {
		return report, err
	}
	expected, err := windows.GetProcessId(s.process)
	if err != nil || pid != expected {
		return report, fmt.Errorf("ответ настройки USB получен от другого процесса: %v", err)
	}
	if report.RunID != s.runID || report.Operation != "usb-driver-setup" {
		return report, fmt.Errorf("ответ настройки USB относится к другому запуску")
	}
	if err := setupAck(ctx, s.pipe, true); err != nil {
		return report, err
	}
	if report.Error != "" {
		return report, fmt.Errorf("настройка WinUSB: %s", cleanSetupError(report.Error))
	}
	return report, nil
}

func (s *usbSetupSession) install(ctx context.Context, target usbSetupDevice) (usbSetupReport, error) {
	var report usbSetupReport
	if err := target.validate(); err != nil {
		return report, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return report, fmt.Errorf("не задан срок настройки USB")
	}
	request := usbSetupCommand{Operation: "usb-driver-setup", RunID: s.runID, Phase: "install", Target: target, Deadline: deadline}
	if err := writeSetupJSON(ctx, s.pipe, request); err != nil {
		return report, err
	}
	report, err := s.receive(ctx)
	if err != nil {
		return report, err
	}
	if err = report.validateInstallation(s.runID, target); err != nil {
		return report, err
	}
	if name, e := driverSetupReport(); e == nil {
		err = AtomicJSON(name, report)
	} else {
		err = e
	}
	return report, err
}

func prepareUSBSetup(ctx context.Context) (session *usbSetupSession, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	pipe, err := createSetupPipe(hex.EncodeToString(nonce[:]))
	if err != nil {
		return nil, fmt.Errorf("создание канала настройки USB: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	s := &usbSetupSession{pipe: pipe, runID: hex.EncodeToString(nonce[:]), ctx: sessionCtx, cancel: cancel}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	// UAC and helper preparation have their own budget. Connection --wait starts
	// only after this handshake and the explicit initial connection instructions.
	startup, stop := context.WithTimeout(sessionCtx, 5*time.Minute)
	defer stop()
	connected := make(chan error, 1)
	go func() { connected <- connectSetupPipe(startup, pipe) }()
	joined := false
	defer func() {
		stop()
		if !joined {
			<-connected
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	s.process, err = launchUSBSetup(exe, s.runID)
	if err != nil {
		return nil, err
	}
	for {
		select {
		case err = <-connected:
			joined = true
			if err != nil {
				return nil, err
			}
			report, e := s.receive(startup)
			if e != nil {
				return nil, e
			}
			if report.Phase != "prepared" || report.Installed || report.Passed {
				return nil, fmt.Errorf("помощник настройки USB не подтвердил подготовку")
			}
			ok = true
			return s, nil
		default:
		}
		if err = startup.Err(); err != nil {
			return nil, err
		}
		state, e := windows.WaitForSingleObject(s.process, 100)
		if e != nil {
			return nil, e
		}
		if state == windows.WAIT_OBJECT_0 {
			// Drain an already completed connect rather than racing a fast child exit.
			select {
			case err = <-connected:
				joined = true
				if err != nil {
					return nil, err
				}
			default:
			}
			return nil, fmt.Errorf("помощник настройки USB завершился до подготовки")
		}
	}
}

func launchUSBSetup(exe, runID string) (windows.Handle, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(strings.Join([]string{windows.EscapeArg("--capsula-usb-setup"), windows.EscapeArg(runID), strconv.Itoa(os.Getpid())}, " "))
	if err != nil {
		return 0, err
	}
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	var launch struct {
		Size, Mask                  uint32
		Window                      uintptr
		Verb, File, Args, Directory *uint16
		Show                        int32
		Instance                    uintptr
		IDList                      uintptr
		Class                       *uint16
		ClassKey                    windows.Handle
		Hotkey                      uint32
		Icon                        uintptr
		Process                     windows.Handle
	}
	launch.Size = uint32(unsafe.Sizeof(launch))
	launch.Mask = 0x40
	launch.Verb, launch.File, launch.Args, launch.Directory = verb, file, args, cwd
	if err = boolCall(windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW"), uintptr(unsafe.Pointer(&launch))); err != nil {
		if err == windows.ERROR_CANCELLED {
			return 0, fmt.Errorf("настройка USB отменена в запросе UAC: %w", err)
		}
		return 0, fmt.Errorf("ShellExecuteExW (UAC): %w", err)
	}
	if launch.Process == 0 {
		return 0, fmt.Errorf("не получен процесс настройки USB")
	}
	return launch.Process, nil
}
