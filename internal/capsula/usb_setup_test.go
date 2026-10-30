package capsula

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func setupTestDevice() usbSetupDevice {
	return usbSetupDevice{ID: `USB\VID_1B8E&PID_C003\5&DEVICE&0&5`, Location: `PCIROOT(0)#USBROOT(0)#USB(5)`, Service: "WinUSB"}
}

func TestUSBSetupPinsDeviceAcrossUAC(t *testing.T) {
	target := setupTestDevice()
	other := target
	other.ID += "-OTHER"
	moved := target
	moved.Location += "#USB(1)"
	for _, tc := range []struct {
		name  string
		nodes []usbSetupDevice
		ready bool
		fail  bool
	}{
		{"absent", nil, false, false},
		{"same", []usbSetupDevice{target}, true, false},
		{"other", []usbSetupDevice{other}, false, true},
		{"moved", []usbSetupDevice{moved}, false, true},
		{"multiple", []usbSetupDevice{target, other}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := selectUSBSetupTarget(target, tc.nodes)
			if ready != tc.ready || (err != nil) != tc.fail {
				t.Fatal(ready, err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	nodes, err := waitUSBSetupTarget(ctx, target, func() ([]usbSetupDevice, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return []usbSetupDevice{target}, nil
	})
	if err != nil || calls != 2 || len(nodes) != 1 {
		t.Fatal(nodes, calls, err)
	}
}

func TestUSBSetupAbsentCancellationAndEnumerationFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := waitUSBSetupTarget(ctx, setupTestDevice(), func() ([]usbSetupDevice, error) { return nil, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	want := errors.New("SetupAPI failure")
	_, err = waitUSBSetupTarget(context.Background(), setupTestDevice(), func() ([]usbSetupDevice, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}

func TestUSBSetupRejectsStaleOrUnconfirmedReports(t *testing.T) {
	target := setupTestDevice()
	run := strings.Repeat("a", 64)
	report := usbSetupReport{Operation: "usb-driver-setup", RunID: run, Passed: true, Installed: true, Target: setupTestDevice(), Phase: "ready", After: []usbSetupDevice{target}}
	if err := report.validate(run, target); err != nil {
		t.Fatal(err)
	}
	stale := report
	stale.RunID = strings.Repeat("b", 64)
	if err := stale.validate(run, target); err == nil {
		t.Fatal("stale report accepted")
	}
	for _, nodes := range [][]usbSetupDevice{nil, {{ID: target.ID, Location: target.Location, Service: "vendor"}}, {target, target}} {
		r := report
		r.After = nodes
		if err := r.validate(run, target); err == nil {
			t.Fatal("unconfirmed report accepted", nodes)
		}
	}
	report.Passed = false
	report.Error = "DiInstallDevice: access denied"
	if err := report.validate(run, target); err == nil || !strings.Contains(err.Error(), "DiInstallDevice") {
		t.Fatal(err)
	}
}

func TestUSBSetupRejectsInvalidTargets(t *testing.T) {
	for _, id := range []string{`USB\VID_1B8E&PID_C003&MI_00\x`, `USB\VID_1B8E&PID_C0030\x`, `PCI\VID_1B8E&PID_C003\x`, "", "x\x00y"} {
		d := setupTestDevice()
		d.ID = id
		if err := d.validate(); err == nil {
			t.Fatal("invalid target accepted", id)
		}
	}
}

func TestUSBSetupInstallationCanAwaitReconnect(t *testing.T) {
	target := setupTestDevice()
	run := strings.Repeat("a", 64)
	r := usbSetupReport{Operation: "usb-driver-setup", RunID: run, Installed: true, Target: target, Phase: "driver-installed"}
	if err := r.validateInstallation(run, target); err != nil {
		t.Fatal("successful driver installation lost across device restart", err)
	}
	if err := r.validate(run, target); err == nil {
		t.Fatal("driver install incorrectly proves USB ready")
	}
	r.Phase, r.Passed, r.After = "ready", true, []usbSetupDevice{target}
	if err := r.validate(run, target); err != nil {
		t.Fatal(err)
	}
}
