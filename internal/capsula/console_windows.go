package capsula

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func commTransfer(ctx context.Context, h windows.Handle, b []byte, write bool, deadline time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	var n uint32
	if write {
		err = windows.WriteFile(h, b, &n, &ov)
	} else {
		err = windows.ReadFile(h, b, &n, &ov)
	}
	if err == windows.ERROR_IO_PENDING {
		waitErr := waitWindowsIO(ctx, h, &ov, deadline)
		err = windows.GetOverlappedResult(h, &ov, &n, true)
		if waitErr != nil {
			err = waitErr
		}
	}
	runtime.KeepAlive(b)
	return int(n), err
}

func (u *USB) exchangeConsole(line, end string, output *bytes.Buffer, timeout time.Duration) error {
	u.closePlatform()
	deadline := time.Now().Add(60 * time.Second)
	var port string
	for {
		nodes, err := windowsUSBNodes("VID_1D6B&PID_0104", true)
		if err != nil {
			return err
		}
		if len(nodes) > 1 {
			return fmt.Errorf("несколько RAM-консолей; оставьте одну Капсулу")
		}
		if len(nodes) == 1 {
			if u.platform.location != "" && u.platform.location != nodes[0].location {
				return fmt.Errorf("RAM-консоль на другом USB пути")
			}
			port = nodes[0].port
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("RAM-консоль не появилась")
		}
		if err = waitContext(u.ctx, 200*time.Millisecond); err != nil {
			return err
		}
	}
	name, err := windows.UTF16PtrFromString(`\\.\` + port)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	// Reserve RX headroom for a burst of NAND metadata. SetupComm is a driver
	// recommendation; continuous reads and error checks are still required.
	if err = windows.SetupComm(h, 1<<20, 1<<16); err != nil {
		return fmt.Errorf("подготовка буферов RAM-консоли: %w", err)
	}
	dcb := windows.DCB{DCBlength: uint32(unsafe.Sizeof(windows.DCB{}))}
	if err = windows.GetCommState(h, &dcb); err != nil {
		return err
	}
	dcb.BaudRate = 115200
	dcb.ByteSize = 8
	dcb.Parity = 0
	dcb.StopBits = 0
	dcb.Flags = 0x1011 // binary, DTR/RTS enabled, no flow control
	if err = windows.SetCommState(h, &dcb); err != nil {
		return err
	}
	timeouts := windows.CommTimeouts{ReadIntervalTimeout: 10, ReadTotalTimeoutConstant: 25, WriteTotalTimeoutConstant: 10000}
	if err = windows.SetCommTimeouts(h, &timeouts); err != nil {
		return err
	}
	write := func(ctx context.Context, data []byte) error {
		deadline := time.Now().Add(10 * time.Second)
		for len(data) > 0 {
			n, e := commTransfer(ctx, h, data, true, deadline)
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
	if err = windows.PurgeComm(h, windows.PURGE_RXCLEAR|windows.PURGE_TXCLEAR); err != nil {
		return err
	}
	// Ignore boot-time errors only before the readiness exchange. From this
	// point on a receive error is fatal, including during the challenge.
	var previousErrors uint32
	if err = windows.ClearCommError(h, &previousErrors, nil); err != nil {
		return err
	}
	u.notice("Ожидание готовности RAM-консоли (до 20 секунд)…")
	return exchangeReadyConsole(u.ctx, consoleStream{
		read: func(ctx context.Context, b []byte) (int, error) {
			return commTransfer(ctx, h, b, false, time.Time{})
		},
		write: write,
		ready: func() {
			u.notice("RAM-консоль готова; ожидание результата операции…")
		},
		status: func() error {
			var flags uint32
			if e := windows.ClearCommError(h, &flags, nil); e != nil {
				return e
			}
			if flags != 0 {
				return fmt.Errorf("ошибка приёма RAM-консоли (COM flags=%#x); ответ неполный, команда автоматически не повторяется", flags)
			}
			return nil
		},
	}, line, end, output, timeout, 20*time.Second, 500*time.Millisecond)
}
