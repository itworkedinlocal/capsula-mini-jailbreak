package capsula

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func platformEntry() (func(), bool, int) {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	if len(os.Args) >= 2 && os.Args[1] == "--capsula-usb-setup" {
		return nil, true, usbSetupEntry(os.Args[2:])
	}
	var processes [2]uint32
	count, _, _ := kernel.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&processes[0])), uintptr(len(processes)))
	standalone := count == 1 && len(os.Args) == 1
	kernel.NewProc("SetConsoleCP").Call(65001)
	kernel.NewProc("SetConsoleOutputCP").Call(65001)
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
	return func() {
		if standalone {
			fmt.Fprint(os.Stdout, "\nНажмите Enter, чтобы закрыть окно. ")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
	}, false, 0
}
