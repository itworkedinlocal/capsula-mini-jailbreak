package capsula

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var winusbDLL = windows.NewLazySystemDLL("winusb.dll")

func usbNotice(message string) { fmt.Fprintln(os.Stderr, message) }

type usbPlatform struct {
	wire            *winUSBWire
	location        string
	setupAttempted  bool
	setupReport     *usbSetupReport
	reconnectNotice bool
	setup           *usbSetupSession
	known           []usbSetupDevice
	prepared        bool
	reconnectAfter  time.Time
	ops             *windowsUSBOperations
	events          []map[string]any
}

// Per-transport dependencies let native regressions exercise the actual wait
// state machine without opening hardware or changing the machine's drivers.
type windowsUSBOperations struct {
	enumerate     func() ([]windowsUSBNode, error)
	configured    func() ([]usbSetupDevice, error)
	interfacePath func(string) (string, error)
	open          func(string) (*winUSBWire, error)
	verify        func() error
	prepare       func(context.Context) (*usbSetupSession, error)
}

func (u *USB) windowsOperations() *windowsUSBOperations {
	if u.platform.ops == nil {
		u.platform.ops = &windowsUSBOperations{}
	}
	o := u.platform.ops
	if o.enumerate == nil {
		o.enumerate = func() ([]windowsUSBNode, error) { return windowsUSBNodes("VID_1B8E&PID_C003", false) }
	}
	if o.configured == nil {
		o.configured = configuredLoaderTargets
	}
	if o.interfacePath == nil {
		o.interfacePath = loaderInterface
	}
	if o.open == nil {
		o.open = openWinUSB
	}
	if o.verify == nil {
		o.verify = u.verifyWindowsLoader
	}
	if o.prepare == nil {
		o.prepare = prepareUSBSetup
	}
	return o
}

type winUSBWire struct {
	file    windows.Handle
	iface   uintptr
	in, out byte
}

func boolCall(proc *windows.LazyProc, args ...uintptr) error {
	r, _, err := proc.Call(args...)
	if r == 0 {
		if err == windows.ERROR_SUCCESS {
			return windows.ERROR_GEN_FAILURE
		}
		return err
	}
	return nil
}
func (w *winUSBWire) close() {
	if w.iface != 0 {
		winusbDLL.NewProc("WinUsb_Free").Call(w.iface)
		w.iface = 0
	}
	if w.file != 0 {
		windows.CloseHandle(w.file)
		w.file = 0
	}
}
func (u *USB) closePlatform() {
	if u.platform.wire != nil {
		u.platform.wire.close()
		u.platform.wire = nil
	}
}

func openWinUSB(path string) (*winUSBWire, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	f, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	w := &winUSBWire{file: f}
	if err = boolCall(winusbDLL.NewProc("WinUsb_Initialize"), uintptr(f), uintptr(unsafe.Pointer(&w.iface))); err != nil {
		w.close()
		return nil, err
	}
	fail := func(e error) (*winUSBWire, error) { w.close(); return nil, e }
	var descriptor [9]byte
	if err = boolCall(winusbDLL.NewProc("WinUsb_QueryInterfaceSettings"), w.iface, 0, uintptr(unsafe.Pointer(&descriptor[0]))); err != nil {
		return fail(err)
	}
	for i := byte(0); i < descriptor[4]; i++ {
		var pipe struct {
			Type     uint32
			ID       byte
			Packet   uint16
			Interval byte
		}
		if err = boolCall(winusbDLL.NewProc("WinUsb_QueryPipe"), w.iface, 0, uintptr(i), uintptr(unsafe.Pointer(&pipe))); err != nil {
			return fail(err)
		}
		if pipe.Type != 2 {
			continue
		}
		if pipe.ID&0x80 != 0 {
			if w.in != 0 {
				return fail(fmt.Errorf("несколько bulk IN endpoints"))
			}
			w.in = pipe.ID
		} else {
			if w.out != 0 {
				return fail(fmt.Errorf("несколько bulk OUT endpoints"))
			}
			w.out = pipe.ID
		}
	}
	if w.in != 0x81 || w.out != 0x02 {
		return fail(fmt.Errorf("неожиданные endpoints загрузчика: %#x/%#x", w.in, w.out))
	}
	return w, nil
}

// Always finish/cancel the OVERLAPPED before releasing its buffer or event.
func waitWindowsIO(ctx context.Context, file windows.Handle, ov *windows.Overlapped, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			_ = windows.CancelIoEx(file, ov)
			return err
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			_ = windows.CancelIoEx(file, ov)
			return context.DeadlineExceeded
		}
		result, err := windows.WaitForSingleObject(ov.HEvent, 100)
		if err != nil {
			_ = windows.CancelIoEx(file, ov)
			return err
		}
		if result == windows.WAIT_OBJECT_0 {
			return nil
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIoEx(file, ov)
			return fmt.Errorf("неверный Windows I/O wait: %d", result)
		}
	}
}
func (w *winUSBWire) transfer(ctx context.Context, proc string, setup uintptr, b []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	var done uint32
	err = boolCall(winusbDLL.NewProc(proc), w.iface, setup, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&done)), uintptr(unsafe.Pointer(&ov)))
	if err == windows.ERROR_IO_PENDING {
		waitErr := waitWindowsIO(ctx, w.file, &ov, time.Time{})
		// TRUE waits for completion after cancellation as well.
		err = boolCall(winusbDLL.NewProc("WinUsb_GetOverlappedResult"), w.iface, uintptr(unsafe.Pointer(&ov)), uintptr(unsafe.Pointer(&done)), 1)
		if waitErr != nil {
			err = waitErr
		}
	}
	runtime.KeepAlive(b)
	return int(done), err
}
func (w *winUSBWire) Control(ctx context.Context, typ, req byte, value, index uint16, b []byte) (int, error) {
	packet := uintptr(typ) | uintptr(req)<<8 | uintptr(value)<<16 | uintptr(index)<<32 | uintptr(len(b))<<48
	return w.transfer(ctx, "WinUsb_ControlTransfer", packet, b)
}
func (w *winUSBWire) Read(ctx context.Context, b []byte) (int, error) {
	return w.transfer(ctx, "WinUsb_ReadPipe", uintptr(w.in), b)
}
func (w *winUSBWire) Write(ctx context.Context, b []byte) (int, error) {
	return w.transfer(ctx, "WinUsb_WritePipe", uintptr(w.out), b)
}

func NewUSB(ctx context.Context, r Resources, folder string) (*USB, error) {
	if err := r.Check(); err != nil {
		return nil, err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	cache = filepath.Join(cache, "Capsula")
	if err = PrivateDir(cache); err != nil {
		return nil, err
	}
	release, err := lockFile(filepath.Join(cache, "usb.lock"))
	if err != nil {
		return nil, err
	}
	return &USB{r: r, folder: folder, ctx: ctx, release: release, memory: map[uint32][]byte{}, bulk: map[string]bool{"echo priming": true, "env export -t 0x2000000": true}, stores: map[string]int64{}}, nil
}

func (u *USB) call(a []string, launch bool) ([]byte, error) {
	if err := u.validate(a); err != nil {
		return nil, err
	}
	if u.platform.wire == nil {
		return nil, fmt.Errorf("USB загрузчик не открыт")
	}
	ctx, cancel := context.WithTimeout(u.ctx, 90*time.Second)
	defer cancel()
	started := time.Now()
	wire := &tracedUSBWire{usbWire: u.platform.wire}
	body, err := protocolCall(ctx, wire, a, launch)
	if e := wire.save(filepath.Join(u.folder, "usb-transfers.jsonl")); e != nil {
		return body, e
	}
	row := map[string]any{"argv": a, "seconds": time.Since(started).Seconds(), "output": string(body)}
	if err != nil {
		row["error"] = err.Error()
	}
	f, e := os.OpenFile(filepath.Join(u.folder, "usb-commands.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	e = json.NewEncoder(f).Encode(row)
	ce := f.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	if launch {
		u.closePlatform()
	}
	return body, err
}

func (u *USB) closeSetup() {
	if u.platform.setup != nil {
		u.platform.setup.close()
		u.platform.setup = nil
	}
	if u.folder != "" && len(u.platform.events) > 0 {
		if err := AtomicJSON(filepath.Join(u.folder, "usb-setup-events.json"), u.platform.events); err != nil {
			u.notice("Не удалось сохранить журнал настройки USB: " + err.Error())
		}
	}
}

func (u *USB) setupEvent(phase string, target *usbSetupDevice, err error) {
	row := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "phase": phase}
	if target != nil {
		row["device"] = *target
	}
	if err != nil {
		row["error"] = cleanSetupError(err.Error())
	}
	u.platform.events = append(u.platform.events, row)
}

func (u *USB) preparePlatform() error {
	if u.platform.prepared {
		return nil
	}
	o := u.windowsOperations()
	nodes, err := o.enumerate()
	if err != nil {
		return err
	}
	if len(nodes) > 1 {
		return fmt.Errorf("обнаружено несколько загрузчиков; оставьте одну Капсулу")
	}
	u.platform.known, err = o.configured()
	if err != nil {
		return err
	}
	// With a present loader the actual port decides, not another cached binding.
	configured := len(u.platform.known) > 0
	if len(nodes) == 1 {
		configured = u.knownLoader(nodes[0])
	}
	if !configured {
		u.setupEvent("preparing", nil, nil)
		u.notice("Подготовка USB Капсулы. Пока не подключайте колонку; подтвердите системный запрос Windows.")
		u.platform.setup, err = o.prepare(u.ctx)
		if err != nil {
			u.setupEvent("prepare-failed", nil, err)
			return err
		}
		u.setupEvent("prepared", nil, nil)
		u.notice("Помощник USB готов. Теперь можно подключить Капсулу по следующей подсказке.")
	}
	if configured {
		u.setupEvent("configured-binding", nil, nil)
	}
	u.platform.prepared = true
	return nil
}

func (u *USB) knownLoader(node windowsUSBNode) bool {
	for _, target := range u.platform.known {
		if strings.EqualFold(target.ID, node.id) && strings.EqualFold(target.Location, node.location) && strings.EqualFold(node.service, "WinUSB") {
			return true
		}
	}
	return false
}

func windowsUSBAccessError(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("нет доступа к WinUSB; проверьте права доступа к устройству: %w", err)
	}
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return fmt.Errorf("USB Капсулы занят другой программой; закройте её и повторите запуск: %w", err)
	}
	return nil
}

func (u *USB) verifyWindowsLoader() error {
	var err error
	body, e := u.call([]string{"identify", "7"}, false)
	if e != nil {
		u.closePlatform()
		return e
	}
	if !bytes.Contains(body, []byte("0-7-0-16-0-0-0")) {
		u.closePlatform()
		return fmt.Errorf("неподдерживаемая версия USB загрузчика")
	}
	if err = waitContext(u.ctx, 500*time.Millisecond); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		if _, err = u.call([]string{"bulkcmd", "echo priming"}, false); err != nil {
			return err
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

func (u *USB) Wait(timeout time.Duration) error {
	u.closePlatform()
	o := u.windowsOperations()
	if !u.platform.prepared {
		if err := u.preparePlatform(); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(timeout)
	var last error
	var selected *usbSetupDevice
	for time.Now().Before(deadline) {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		nodes, err := o.enumerate()
		if err != nil {
			return err
		}
		if len(nodes) > 1 {
			return fmt.Errorf("обнаружено несколько загрузчиков; оставьте одну Капсулу")
		}
		if selected != nil {
			if _, err = selectUSBSetupTarget(*selected, snapshots(nodes)); err != nil {
				return err
			}
		}
		if len(nodes) == 1 {
			node := nodes[0]
			if u.platform.location != "" && !strings.EqualFold(node.location, u.platform.location) {
				return fmt.Errorf("загрузчик появился на другом USB пути; верните Капсулу в тот же разъём")
			}
			if selected == nil {
				target := node.snapshot()
				selected = &target
				u.setupEvent("selected", selected, nil)
			}
			path, e := o.interfacePath(node.id)
			if e == nil && strings.EqualFold(node.service, "WinUSB") {
				u.platform.wire, e = o.open(path)
				if access := windowsUSBAccessError(e); access != nil {
					return access
				}
			}
			if u.platform.wire != nil {
				u.platform.location = node.location
				if err = o.verify(); err != nil {
					u.setupEvent("verification-failed", selected, err)
					u.closePlatform()
					return err
				}
				if report := u.platform.setupReport; report != nil {
					report.After = []usbSetupDevice{node.snapshot()}
					report.Phase, report.Passed = "ready", true
					report.Time = Now()
					if err = report.validate(report.RunID, *selected); err != nil {
						return err
					}
					name, e := driverSetupReport()
					if e != nil {
						return e
					}
					if err = AtomicJSON(name, report); err != nil {
						return err
					}
					u.platform.setupReport = nil
				}
				u.setupEvent("ready", selected, nil)
				u.closeSetup()
				u.notice("Капсула найдена. USB-кабель не отключайте.")
				return nil
			}
			last = e
			// A missing interface on a configured WinUSB binding is transient. Never
			// reinstall the driver because open/permissions/enumeration is delayed.
			if !u.knownLoader(node) && !u.platform.setupAttempted {
				u.platform.setupAttempted = true
				u.platform.location = node.location
				if u.platform.setup == nil {
					// A different, previously unconfigured port was selected after preflight.
					u.notice("Этот USB-разъём ещё не настроен. Подтвердите системный запрос Windows; дождитесь следующей подсказки.")
					u.platform.setup, err = o.prepare(u.ctx)
					if err != nil {
						return err
					}
					// UAC must not consume the subsequent connection budget.
					deadline = time.Now().Add(timeout)
					current, e := o.enumerate()
					if e != nil {
						return e
					}
					ready, e := selectUSBSetupTarget(*selected, snapshots(current))
					if e != nil {
						return e
					}
					if !ready {
						u.requestSetupReconnect()
					}
				}
				installCtx, cancel := context.WithDeadline(u.ctx, deadline)
				u.setupEvent("installing", selected, nil)
				report, e := u.platform.setup.install(installCtx, *selected)
				cancel()
				u.setupEvent("installation-result", selected, e)
				u.closeSetup()
				if e != nil {
					return fmt.Errorf("настройка USB: %w", e)
				}
				u.platform.setupReport = &report
				u.platform.reconnectAfter = time.Now().Add(2 * time.Second)
				deadline = time.Now().Add(timeout)
				u.notice("Драйвер установлен. Ожидаю USB Капсулы; пока не отключайте кабель.")
				continue
			}
		}
		if u.platform.setupReport != nil && !u.platform.reconnectNotice && time.Now().After(u.platform.reconnectAfter) {
			u.requestSetupReconnect()
		}
		if err := waitContext(u.ctx, 20*time.Millisecond); err != nil {
			return err
		}
	}
	if last != nil && !errors.Is(last, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("WinUSB недоступен после ожидания: %w", last)
	}
	return fmt.Errorf("%w: загрузчик A113X не найден; журнал настройки сохранён", ErrLoaderTimeout)
}

func snapshots(nodes []windowsUSBNode) []usbSetupDevice {
	out := make([]usbSetupDevice, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.snapshot())
	}
	return out
}

func (u *USB) requestSetupReconnect() {
	if u.platform.reconnectNotice {
		return
	}
	u.platform.reconnectNotice = true
	u.setupEvent("reconnect-requested", nil, nil)
	u.notice("Сейчас переподключите Капсулу: отключите USB на 10 секунд и подключите снова в тот же разъём. Штатный блок питания не подключайте. Утилиту перезапускать не нужно.")
}

func (u *USB) RAMAvailable() bool {
	nodes, err := windowsUSBNodes("VID_1D6B&PID_0104", true)
	return err == nil && len(nodes) == 1 && (u.platform.location == "" || nodes[0].location == u.platform.location)
}
