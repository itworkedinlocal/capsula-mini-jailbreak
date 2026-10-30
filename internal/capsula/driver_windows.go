package capsula

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const loaderGUIDString = "{D576C8A3-8CE8-4E73-96A3-FD6EBF7C22E1}"

var loaderGUID = windows.GUID{Data1: 0xd576c8a3, Data2: 0x8ce8, Data3: 0x4e73, Data4: [8]byte{0x96, 0xa3, 0xfd, 0x6e, 0xbf, 0x7c, 0x22, 0xe1}}
var cfgmgr = windows.NewLazySystemDLL("cfgmgr32.dll")
var setupapi = windows.NewLazySystemDLL("setupapi.dll")

type windowsUSBNode struct {
	id, service, location, port string
	status, problem             uint32
}

func (n windowsUSBNode) snapshot() usbSetupDevice {
	return usbSetupDevice{ID: n.id, Location: n.location, Service: n.service, Status: n.status, Problem: n.problem}
}

func loaderSetupSnapshot() ([]usbSetupDevice, error) {
	nodes, err := windowsUSBNodes("VID_1B8E&PID_C003", false)
	out := make([]usbSetupDevice, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.snapshot())
	}
	return out, err
}

func registryStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	}
	return nil
}
func deviceLocation(set windows.DevInfo, info *windows.DevInfoData) string {
	v, err := set.DeviceRegistryProperty(info, windows.SPDRP_LOCATION_PATHS)
	if err != nil {
		return ""
	}
	values := registryStrings(v)
	if len(values) == 0 {
		return ""
	}
	location := strings.ToUpper(values[0])
	if n := strings.Index(location, "#USBMI("); n >= 0 {
		location = location[:n]
	}
	return location
}
func ramSerial(dev windows.DEVINST) bool {
	for n := 0; n < 5; n++ {
		var id [512]uint16
		code, _, _ := cfgmgr.NewProc("CM_Get_Device_IDW").Call(uintptr(dev), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
		if code != 0 {
			return false
		}
		s := strings.ToUpper(windows.UTF16ToString(id[:]))
		if strings.HasPrefix(s, `USB\VID_1D6B&PID_0104\`) && strings.HasSuffix(s, `\CAPSULA-RAMBOOT`) {
			return true
		}
		var parent windows.DEVINST
		code, _, _ = cfgmgr.NewProc("CM_Get_Parent").Call(uintptr(unsafe.Pointer(&parent)), uintptr(dev), 0)
		if code != 0 {
			return false
		}
		dev = parent
	}
	return false
}

func windowsUSBNodes(vidpid string, console bool) ([]windowsUSBNode, error) {
	return enumerateWindowsUSB(vidpid, console, true)
}

func enumerateWindowsUSB(vidpid string, console, present bool) ([]windowsUSBNode, error) {
	flags := windows.DIGCF_ALLCLASSES
	if present {
		flags |= windows.DIGCF_PRESENT
	}
	set, err := windows.SetupDiGetClassDevsEx(nil, "USB", 0, flags, 0, "")
	if err != nil {
		return nil, err
	}
	defer set.Close()
	var nodes []windowsUSBNode
	for n := 0; ; n++ {
		info, err := set.EnumDeviceInfo(n)
		if err == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if err != nil {
			return nil, err
		}
		id, err := set.DeviceInstanceID(info)
		if err != nil {
			return nil, err
		}
		upper := strings.ToUpper(id)
		parts := strings.Split(upper, `\`)
		if len(parts) < 3 || parts[0] != "USB" || (parts[1] != vidpid && !(console && strings.HasPrefix(parts[1], vidpid+"&MI_"))) {
			continue
		}
		if !console && strings.Contains(strings.Split(upper, `\`)[1], "&MI_") {
			continue
		}
		node := windowsUSBNode{id: id, location: deviceLocation(set, info)}
		if e := windows.CM_Get_DevNode_Status(&node.status, &node.problem, info.DevInst, 0); e != nil && present {
			return nil, fmt.Errorf("CM_Get_DevNode_Status %s: %w", id, e)
		}
		if node.location == "" {
			if !present {
				continue
			}
			return nil, fmt.Errorf("не определён физический USB путь %s", id)
		}
		if v, e := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE); e == nil {
			if values := registryStrings(v); len(values) > 0 {
				node.service = values[0]
			}
		}
		if console {
			if !ramSerial(info.DevInst) {
				continue
			}
			h, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DEV, windows.KEY_QUERY_VALUE)
			if e != nil {
				continue
			}
			key := registry.Key(h)
			node.port, _, e = key.GetStringValue("PortName")
			key.Close()
			if e != nil || !strings.HasPrefix(node.port, "COM") {
				continue
			}
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func loaderInterface(id string) (string, error) {
	instance, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return "", err
	}
	for attempts := 0; attempts < 3; attempts++ {
		var size uint32
		code, _, _ := cfgmgr.NewProc("CM_Get_Device_Interface_List_SizeW").Call(uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&loaderGUID)), uintptr(unsafe.Pointer(instance)), 0)
		if code != 0 {
			return "", fmt.Errorf("CM interface size: %#x", code)
		}
		if size < 2 || size > 65536 {
			return "", windows.ERROR_FILE_NOT_FOUND
		}
		list := make([]uint16, size)
		code, _, _ = cfgmgr.NewProc("CM_Get_Device_Interface_ListW").Call(uintptr(unsafe.Pointer(&loaderGUID)), uintptr(unsafe.Pointer(instance)), uintptr(unsafe.Pointer(&list[0])), uintptr(size), 0)
		if code == 0 {
			path := windows.UTF16ToString(list)
			if path == "" {
				return "", windows.ERROR_FILE_NOT_FOUND
			}
			return path, nil
		}
		if code != 0x1a {
			return "", fmt.Errorf("CM interface list: %#x", code)
		} // CR_BUFFER_SMALL
	}
	return "", fmt.Errorf("USB interface list изменяется")
}

// The expensive, device-independent driver preparation happens before the
// initial connection prompt. The helper cannot change a device at this stage.
type preparedLoaderDriver struct {
	set windows.DevInfo
}

func prepareLoaderDriver() (*preparedLoaderDriver, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, fmt.Errorf("нужны права администратора для настройки USB")
	}

	set, err := windows.SetupDiCreateDeviceInfoListEx(nil, 0, "")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			set.Close()
		}
	}()

	params, err := set.DeviceInstallParams(nil)
	if err != nil {
		return nil, err
	}
	windir, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	if err = params.SetDriverPath(filepath.Join(windir, "INF", "winusb.inf")); err != nil {
		return nil, err
	}
	params.Flags |= windows.DI_ENUMSINGLEINF | windows.DI_QUIETINSTALL
	params.FlagsEx |= windows.DI_FLAGSEX_ALLOWEXCLUDEDDRVS
	if err = set.SetDeviceInstallParams(nil, params); err != nil {
		return nil, err
	}
	if err = set.BuildDriverInfoList(nil, windows.SPDIT_CLASSDRIVER); err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			set.DestroyDriverInfoList(nil, windows.SPDIT_CLASSDRIVER)
		}
	}()
	var selected *windows.DrvInfoData
	for n := 0; ; n++ {
		driver, e := set.EnumDriverInfo(nil, windows.SPDIT_CLASSDRIVER, n)
		if e == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if e != nil {
			return nil, e
		}
		detail, e := set.DriverInfoDetail(nil, driver)
		if e != nil {
			return nil, e
		}
		if strings.EqualFold(filepath.Clean(detail.InfFileName()), filepath.Join(windir, "INF", "winusb.inf")) && strings.Contains(strings.ToLower(detail.SectionName()), "winusb") {
			selected = driver
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("штатный WinUSB driver отсутствует")
	}

	if err = set.SetSelectedDriver(nil, selected); err != nil {
		return nil, err
	}
	ok = true
	return &preparedLoaderDriver{set: set}, nil
}

func (d *preparedLoaderDriver) close() {
	d.set.DestroyDriverInfoList(nil, windows.SPDIT_CLASSDRIVER)
	d.set.Close()
}

// The parent sends the selected instance only after the helper is prepared.
// Absence is waited out under the parent's connection deadline, never replayed.
func (d *preparedLoaderDriver) install(ctx context.Context, target usbSetupDevice) (err error) {
	stage := "wait-selected-loader"
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s: %w", stage, err)
		}
	}()
	if _, err = waitUSBSetupTarget(ctx, target, loaderSetupSnapshot); err != nil {
		return err
	}
	set := d.set
	var info windows.DevInfoData
	*(*uint32)(unsafe.Pointer(&info)) = uint32(unsafe.Sizeof(info))
	id, err := windows.UTF16PtrFromString(target.ID)
	if err != nil {
		return err
	}
	stage = "SetupDiOpenDeviceInfoW"
	// Inherit the fixed global driver list into this device's own list. An
	// associated USBDevice class on the set would reject an existing vendor class.

	if err = boolCall(setupapi.NewProc("SetupDiOpenDeviceInfoW"), uintptr(set), uintptr(unsafe.Pointer(id)), 0, 2, uintptr(unsafe.Pointer(&info))); err != nil {
		return err
	}
	selected, err := windows.SetupDiGetSelectedDriver(set, &info)
	if err != nil {
		return err
	}
	if err = set.SetSelectedDriver(&info, selected); err != nil {
		return err
	}
	deviceParams, err := set.DeviceInstallParams(&info)
	if err != nil {
		return err
	}
	deviceParams.Flags |= windows.DI_QUIETINSTALL
	if err = set.SetDeviceInstallParams(&info, deviceParams); err != nil {
		return err
	}

	stage = "DeviceInterfaceGUIDs"
	h, err := set.OpenDevRegKey(&info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DEV, windows.KEY_QUERY_VALUE|windows.KEY_SET_VALUE)
	if err != nil {
		return err
	}
	key := registry.Key(h)
	guids, _, e := key.GetStringsValue("DeviceInterfaceGUIDs")
	if e != nil && e != windows.ERROR_FILE_NOT_FOUND {
		key.Close()
		return e
	}
	found := false
	for _, guid := range guids {
		found = found || strings.EqualFold(guid, loaderGUIDString)
	}
	if !found {
		guids = append(guids, loaderGUIDString)
	}
	err = key.SetStringsValue("DeviceInterfaceGUIDs", guids)
	key.Close()
	if err != nil {
		return err
	}
	stage = "DiInstallDevice"
	var reboot uint32
	err = boolCall(windows.NewLazySystemDLL("newdev.dll").NewProc("DiInstallDevice"), 0, uintptr(set), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(selected)), 0, uintptr(unsafe.Pointer(&reboot)))
	if err != nil {
		return err
	}
	if reboot != 0 {
		return fmt.Errorf("Windows требует перезапуск компьютера для настройки USB")
	}
	return nil
}

// Configuration is only a preflight hint. Wait still verifies the live interface
// and two actual RAM reads; a JSON receipt never establishes driver readiness.
func configuredLoaderTargets() ([]usbSetupDevice, error) {
	nodes, err := enumerateWindowsUSB("VID_1B8E&PID_C003", false, false)
	if err != nil {
		return nil, err
	}
	var targets []usbSetupDevice
	for _, node := range nodes {
		if !strings.EqualFold(node.service, "WinUSB") {
			continue
		}
		key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+node.id+`\Device Parameters`, registry.QUERY_VALUE)
		if e != nil {
			continue
		}
		guids, _, e := key.GetStringsValue("DeviceInterfaceGUIDs")
		key.Close()
		if e != nil {
			continue
		}
		for _, guid := range guids {
			if strings.EqualFold(guid, loaderGUIDString) {
				targets = append(targets, node.snapshot())
				break
			}
		}
	}
	return targets, nil
}
