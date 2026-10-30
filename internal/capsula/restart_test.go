package capsula

import (
	"strings"
	"testing"
)

func knownBootEnv() map[string]string {
	return map[string]string{
		"bootcmd":         "run storeboot",
		"preboot":         "run switch_bootmode;",
		"switch_bootmode": "get_rebootmode;if test ${reboot_mode} = factory_reset; then run recovery_from_flash;else if test ${reboot_mode} = update; then run update;else if test ${reboot_mode} = cold_boot; then run try_auto_burn; else if test ${reboot_mode} = fastboot; then fastboot;fi;fi;fi;fi;",
		"try_auto_burn":   "update 700 450;",
	}
}
func TestAutomaticRestartBootPolicy(t *testing.T) {
	if !automaticBootSupported(knownBootEnv()) {
		t.Fatal("known boot policy not accepted")
	}
	for key, value := range map[string]string{"bootcmd": "run update", "preboot": "", "try_auto_burn": "run update", "switch_bootmode": "run recovery_from_flash", "recovery_status": "in_progress", "upgrade_step": "3"} {
		env := knownBootEnv()
		env[key] = value
		if automaticBootSupported(env) {
			t.Fatal("unsafe boot policy", key)
		}
	}
	if automaticBootSupported(nil) {
		t.Fatal("unknown firmware accepted")
	}
}
func TestAutomaticRootTransitionsNeedNoManualReconnect(t *testing.T) {
	b, m := modelBackend(t, "simple")
	m.bootEnv = knownBootEnv()
	b.Reconnect = func(string) error { t.Fatal("manual reconnect for supported firmware"); return nil }
	out, err := b.Execute("root", false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.InstallationCompleted || !out.StorageClean {
		t.Fatal("installation incomplete")
	}
	count := 0
	for _, event := range m.events {
		if event == "restart" {
			count++
		}
	}
	if count < 3 {
		t.Fatal("expected multiple automatic RAM transitions", count)
	}
}
func TestAutomaticRestartLostACKNeverReplays(t *testing.T) {
	b, m := modelBackend(t, "fast")
	m.bootEnv = knownBootEnv()
	m.restartLostACK = true
	b.Reconnect = func(string) error { t.Fatal("lost ACK caused manual replay"); return nil }
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range m.events {
		if event == "restart" {
			count++
		}
	}
	if count != 2 {
		t.Fatal("restart command replayed", count)
	}
}
func TestAutomaticRestartTimeoutHasManualFallback(t *testing.T) {
	b, m := modelBackend(t, "fast")
	m.bootEnv = knownBootEnv()
	m.restartTimeouts = 1
	calls := 0
	b.Reconnect = func(string) error { calls++; return nil }
	if _, err := b.Execute("root", false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unexpected manual fallback", calls)
	}
}
func TestAutomaticRestartRefusesDirtyStorage(t *testing.T) {
	b, m := modelBackend(t, "fast")
	m.bootEnv = knownBootEnv()
	m.restartDirty = true
	b.Reconnect = func(string) error { t.Fatal("dirty storage suggested unplug"); return nil }
	if _, err := b.Execute("root", false); err == nil {
		t.Fatal("dirty reboot accepted")
	}
	for _, event := range m.events {
		if event == "restart" || event == "install" {
			t.Fatal("reboot/write after dirty refusal")
		}
	}
}
func TestAutomaticRestartRechecksIdentityAndSlot(t *testing.T) {
	for _, kind := range []string{"identity", "slot"} {
		t.Run(kind, func(t *testing.T) {
			b, m := modelBackend(t, "fast")
			m.bootEnv = knownBootEnv()
			// Enrollment transition has no stock slot yet; change on the second
			// transition, after inspection. The identity check applies to both.
			if kind == "identity" {
				m.restartWrongIdentity = true
			} else {
				m.restartSlot = "a"
			}
			_, err := b.Execute("root", false)
			if err == nil || !strings.Contains(err.Error(), map[string]string{"identity": "устройство/разметка", "slot": "слот"}[kind]) {
				t.Fatal("changed target accepted", err)
			}
			for _, event := range m.events {
				if event == "install" {
					t.Fatal("wrote after identity/slot change")
				}
			}
		})
	}
}

func TestAutomaticFallbackRefusesNewlyDirtyRAM(t *testing.T) {
	b, m := modelBackend(t, "fast")
	m.bootEnv = knownBootEnv()
	m.restartTimeouts = 1
	m.restartDirtyOnTimeout = true
	b.Reconnect = func(string) error { t.Fatal("suggested unplug with newly dirty RAM"); return nil }
	if _, err := b.Execute("root", false); err == nil {
		t.Fatal("unsafe fallback accepted")
	}
	for _, event := range m.events {
		if event == "install" {
			t.Fatal("write after unsafe fallback")
		}
	}
}
