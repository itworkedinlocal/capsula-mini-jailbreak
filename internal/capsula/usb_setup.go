package capsula

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type usbSetupDevice struct {
	ID       string `json:"instance_id"`
	Location string `json:"physical_path"`
	Service  string `json:"service,omitempty"`
	Status   uint32 `json:"status,omitempty"`
	Problem  uint32 `json:"problem,omitempty"`
}

type usbSetupCommand struct {
	Operation string         `json:"operation"`
	RunID     string         `json:"run_id"`
	Phase     string         `json:"phase"`
	Target    usbSetupDevice `json:"selected_device"`
	Deadline  time.Time      `json:"deadline"`
}

type usbSetupReport struct {
	Operation string           `json:"operation"`
	RunID     string           `json:"run_id"`
	Time      string           `json:"time"`
	Passed    bool             `json:"passed"`
	Phase     string           `json:"phase"`
	Installed bool             `json:"driver_installed"`
	Target    usbSetupDevice   `json:"selected_device"`
	Error     string           `json:"error,omitempty"`
	Before    []usbSetupDevice `json:"before"`
	After     []usbSetupDevice `json:"after"`
}

func cleanSetupError(message string) string {
	return strings.Map(func(c rune) rune {
		if c < 32 || c == 127 {
			return ' '
		}
		return c
	}, message)
}

func (d usbSetupDevice) validate() error {
	parts := strings.Split(strings.ToUpper(d.ID), `\`)
	if len(parts) != 3 || parts[0] != "USB" || parts[1] != "VID_1B8E&PID_C003" || parts[2] == "" || d.Location == "" || len(d.ID) > 512 || len(d.Location) > 4096 || strings.ContainsAny(d.ID+d.Location, "\x00\r\n") {
		return fmt.Errorf("неверное выбранное USB устройство")
	}
	return nil
}

// Only absence is transient. A different loader is never silently selected.
func selectUSBSetupTarget(target usbSetupDevice, nodes []usbSetupDevice) (bool, error) {
	if err := target.validate(); err != nil {
		return false, err
	}
	if len(nodes) == 0 {
		return false, nil
	}
	if len(nodes) != 1 {
		return false, fmt.Errorf("обнаружено несколько загрузчиков; оставьте одну Капсулу")
	}
	if !strings.EqualFold(nodes[0].ID, target.ID) || !strings.EqualFold(nodes[0].Location, target.Location) {
		return false, fmt.Errorf("USB устройство изменилось во время настройки; верните выбранную Капсулу в тот же разъём")
	}
	return true, nil
}

func waitUSBSetupTarget(ctx context.Context, target usbSetupDevice, enumerate func() ([]usbSetupDevice, error)) ([]usbSetupDevice, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("выбранный USB загрузчик не появился после UAC: %w", err)
		}
		nodes, err := enumerate()
		if err != nil {
			return nodes, fmt.Errorf("перечисление USB после UAC: %w", err)
		}
		ready, err := selectUSBSetupTarget(target, nodes)
		if err != nil || ready {
			return nodes, err
		}
		if err := waitContext(ctx, 200*time.Millisecond); err != nil {
			return nodes, fmt.Errorf("выбранный USB загрузчик исчез во время UAC; отключите USB на 10 секунд и подключите снова: %w", err)
		}
	}
}

func (r usbSetupReport) validate(runID string, target usbSetupDevice) error {
	if err := r.validateInstallation(runID, target); err != nil {
		return err
	}
	if !r.Passed || r.Phase != "ready" {
		return fmt.Errorf("WinUSB ещё ожидает переподключения")
	}
	ready, err := selectUSBSetupTarget(target, r.After)
	if err != nil {
		return err
	}
	if !ready || !strings.EqualFold(r.After[0].Service, "WinUSB") {
		return fmt.Errorf("настройка не подтвердила выбранный WinUSB интерфейс")
	}
	return nil
}

func (r usbSetupReport) validateInstallation(runID string, target usbSetupDevice) error {
	if r.RunID != runID || r.Operation != "usb-driver-setup" {
		return fmt.Errorf("ответ настройки USB относится к другому запуску")
	}
	if r.Error != "" {
		return fmt.Errorf("настройка WinUSB: %s", cleanSetupError(r.Error))
	}
	ready, err := selectUSBSetupTarget(target, []usbSetupDevice{r.Target})
	if err != nil {
		return err
	}
	if !ready || !r.Installed || (r.Phase != "driver-installed" && r.Phase != "ready") {
		return fmt.Errorf("установка WinUSB не подтверждена")
	}
	return nil
}
