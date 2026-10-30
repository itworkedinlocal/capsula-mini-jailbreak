package capsula

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

type skipFlags []string

func (s *skipFlags) String() string     { return strings.Join(*s, ",") }
func (s *skipFlags) Set(v string) error { *s = append(*s, v); return nil }

type Terminal struct {
	Input  *os.File
	Output io.Writer
	Reader *bufio.Reader
	Ctx    context.Context
}

func (t *Terminal) Line(prompt string) (string, error) {
	fmt.Fprint(t.Output, prompt)
	var line string
	var e error
	if t.Ctx == nil {
		line, e = t.Reader.ReadString('\n')
	} else {
		type answer struct {
			line string
			err  error
		}
		done := make(chan answer, 1)
		go func() { s, e := t.Reader.ReadString('\n'); done <- answer{s, e} }()
		select {
		case a := <-done:
			line, e = a.line, a.err
		case <-t.Ctx.Done():
			return "", t.Ctx.Err()
		}
	}
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(line), nil
}
func (t *Terminal) Interactive() bool { return term.IsTerminal(int(t.Input.Fd())) }
func (t *Terminal) Password(confirm bool) ([]byte, error) {
	if !t.Interactive() {
		return nil, fmt.Errorf("пароль вводится скрыто в локальном терминале")
	}
	fmt.Fprint(t.Output, "Пароль root для SSH Капсулы: ")
	pw, e := t.readSecret()
	fmt.Fprintln(t.Output)
	if e != nil {
		return nil, e
	}
	if e = ValidatePassword(pw); e != nil {
		clear(pw)
		return nil, e
	}
	if confirm {
		fmt.Fprint(t.Output, "Повторите пароль: ")
		again, e := t.readSecret()
		fmt.Fprintln(t.Output)
		if e != nil {
			clear(pw)
			return nil, e
		}
		same := string(pw) == string(again)
		clear(again)
		if !same {
			clear(pw)
			return nil, fmt.Errorf("пароли не совпали")
		}
	}
	return pw, nil
}

func (t *Terminal) readSecret() ([]byte, error) {
	fd := int(t.Input.Fd())
	if t.Ctx == nil {
		return term.ReadPassword(fd)
	}
	if e := t.Ctx.Err(); e != nil {
		return nil, e
	}
	state, e := term.GetState(fd)
	if e != nil {
		return nil, e
	}
	defer term.Restore(fd, state)
	type answer struct {
		data []byte
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		b, e := term.ReadPassword(fd)
		select {
		case <-t.Ctx.Done():
			clear(b)
		case done <- answer{b, e}:
		}
	}()
	select {
	case a := <-done:
		return a.data, a.err
	case <-t.Ctx.Done():
		return nil, t.Ctx.Err()
	}
}

// Confirm accepts only one-letter choices. Enter always declines.
func (t *Terminal) Confirm(prompt string) (bool, error) {
	for {
		answer, err := t.Line(prompt + " [y/N]: ")
		if err != nil {
			return false, err
		}
		switch answer {
		case "y", "Y":
			return true, nil
		case "", "n", "N":
			return false, nil
		default:
			fmt.Fprintln(t.Output, "Введите y или n; Enter — отказ.")
		}
	}
}
func (t *Terminal) ConfirmPolicy(p Policy) error {
	if p.Mode == "simple" {
		return nil
	}
	if !t.Interactive() {
		return fmt.Errorf("режим %s требует предупреждения и подтверждения в терминале", p.Mode)
	}
	if p.Mode == "fast" {
		fmt.Fprintln(t.Output, "БЫСТРЫЙ РЕЖИМ: восстановительный бэкап не создаётся. Полный аудит NAND и пробная запись пропущены. При сбое можно потерять данные; восстановление не гарантируется.")
	} else {
		fmt.Fprintln(t.Output, ExpertWarning)
		fmt.Fprintln(t.Output, "Отключённые этапы:", strings.Join(p.Skip, ", "))
	}
	accepted, err := t.Confirm("Продолжить в режиме " + p.Mode + "?")
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("режим %s отменён", p.Mode)
	}
	return nil
}
func (t *Terminal) BeforeWrite(id, op string, p Policy) error {
	fmt.Fprintf(t.Output, "\nУстройство: %s\nОперация: %s, запись только в data\nРежим: %s\n", id, op, p.Mode)
	if len(p.Skip) > 0 {
		fmt.Fprintln(t.Output, "Отключённые проверки:", strings.Join(p.Skip, ", "))
	}
	if p.Mode == "expert" {
		accepted, err := t.Confirm("Выполнить эту запись с выбранными пропусками?")
		if err != nil {
			return err
		}
		if !accepted {
			return fmt.Errorf("запись отменена")
		}
	}
	return nil
}
func (t *Terminal) Reconnect(message string) error {
	if !t.Interactive() {
		return fmt.Errorf("для переподключения нужен локальный терминал")
	}
	fmt.Fprintf(t.Output, "\n%s\n1. Отключите USB и штатный блок питания на 10 секунд.\n2. Подключите только USB-кабель данных к компьютеру.\nПодключение обнаружится автоматически; Enter не нужен. Выход — Ctrl+C.\n", message)
	return nil
}

func ChooseDevice(store *Store, wanted string) (string, error) {
	if wanted != "" {
		if !digestRE.MatchString(wanted) {
			return "", fmt.Errorf("неверный --device")
		}
		d, e := store.Device(wanted)
		if e != nil {
			return "", e
		}
		if !Exists(filepath.Join(d, "installed.json")) {
			return "", fmt.Errorf("нет сохранённой установки выбранного устройства")
		}
		return wanted, nil
	}
	entries, e := os.ReadDir(store.Root)
	if e != nil {
		return "", e
	}
	var ids []string
	for _, entry := range entries {
		if !digestRE.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if Exists(filepath.Join(store.Root, entry.Name(), "installed.json")) {
			ids = append(ids, entry.Name())
		}
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("найдено устройств: %d; укажите --device ID", len(ids))
	}
	return ids[0], nil
}
func SSHOperation(ctx context.Context, store *Store, id, host string, port int, level string, pw []byte) (SSHReport, error) {
	device, e := store.Device(id)
	if e != nil {
		return SSHReport{}, e
	}
	unlock, e := store.Lock(id)
	if e != nil {
		return SSHReport{}, e
	}
	defer unlock()
	var installed Installed
	if e = ReadSealed(filepath.Join(device, "installed.json"), &installed); e != nil {
		return SSHReport{}, e
	}
	if installed.State != "active" || installed.Identity != id {
		return SSHReport{}, fmt.Errorf("нет активного индивидуального пакета")
	}
	work, e := store.Run(id, "verify")
	if e != nil {
		return SSHReport{}, e
	}
	// Establish root before diagnosing local package/full acceptance failures.
	report, e := VerifySSH(ctx, host, port, installed.PublicKey, pw, work, "basic", nil)
	if e == nil && level == "full" {
		packagePath, pe := SafeJoin(device, installed.Package)
		var m *Manifest
		if pe == nil {
			m, pe = ValidatePackage(packagePath, id, true)
		}
		if pe == nil && m.ArchiveSHA != installed.ArchiveSHA {
			pe = fmt.Errorf("локальный пакет изменён после установки")
		}
		if pe != nil {
			e = fmt.Errorf("локальный пакет для полной проверки: %w", pe)
			report.Level = "full"
			report.Error = e.Error()
			report.Stages["local-package"] = SSHStage{Status: "failed", Error: pe.Error()}
		} else {
			report, e = VerifySSH(ctx, host, port, installed.PublicKey, pw, work, "full", m)
		}
	}
	if e != nil {
		report.Error = e.Error()
	}
	if le := AtomicJSON(filepath.Join(work, "result.json"), report); le != nil {
		return report, le
	}
	phase := "verified"
	if e != nil {
		phase = "failed"
	}
	if le := AtomicJSON(filepath.Join(work, "session.json"), map[string]any{"operation": "verify", "phase": phase, "error": report.Error, "ssh_root_verified": report.Root, "ssh_full_verified": report.Full}); le != nil {
		return report, le
	}
	if report.Full {
		if le := SaveSealed(filepath.Join(device, "last-ssh-verification.json"), report); le != nil {
			return report, le
		}
	}
	return report, e
}
func (t *Terminal) AfterInstall(ctx context.Context, store *Store, out *Outcome) error {
	fmt.Fprintln(t.Output, "\nЗапись завершена · переход к штатному питанию\n\n  1. ОТСОЕДИНИТЕ USB-кабель от Капсулы.\n  2. ПОДКЛЮЧИТЕ ШТАТНЫЙ БЛОК ПИТАНИЯ.\n  3. Дождитесь загрузки и подключения к Wi-Fi.\n\nПроверка SSH необязательна; её ошибка не отменяет установку.")
	if !out.Policy.Enabled("ssh") {
		return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
	}
	host, e := t.Line("IP или имя Капсулы (Enter — пропустить SSH): ")
	if e != nil || host == "" {
		out.Stages["ssh"] = StageResult{"skipped", "пропущено владельцем"}
		return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
	}
	for {
		pw, e := t.Password(false)
		if e == nil {
			var report SSHReport
			report, e = SSHOperation(ctx, store, out.Identity, host, 22, "full", pw)
			clear(pw)
			out.SSHRootVerified = report.Root
			out.SSHFullVerified = report.Full
		}
		if e == nil {
			out.Stages["ssh"] = StageResult{Status: "passed"}
			fmt.Fprintln(t.Output, "Root SSH и расширенная проверка пройдены.")
			return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
		}
		out.Stages["ssh"] = StageResult{"failed", e.Error()}
		if le := AtomicJSON(filepath.Join(out.Run, "result.json"), out); le != nil {
			return le
		}
		if ctx.Err() != nil {
			out.Stages["ssh"] = StageResult{"skipped", "прервано владельцем"}
			return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
		}
		if out.SSHRootVerified {
			fmt.Fprintln(t.Output, "SSH root работает. Расширенная проверка пока не пройдена.")
		} else {
			fmt.Fprintln(t.Output, "Проверка SSH пока не завершена. Проверьте штатное питание, Wi-Fi, IP и пароль.")
		}
		fmt.Fprintln(t.Output, "Причина:", e)
		again, e := t.Confirm("Повторить проверку SSH?")
		if e != nil || !again {
			out.Stages["ssh"] = StageResult{"skipped", "расширенная проверка пропущена; предыдущий результат сохранён"}
			return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
		}
		address, e := t.Line("IP или имя Капсулы [" + host + "]: ")
		if e != nil {
			out.Stages["ssh"] = StageResult{"skipped", "прервано владельцем"}
			return AtomicJSON(filepath.Join(out.Run, "result.json"), out)
		}
		if address != "" {
			host = address
		}
	}
}

func Main(args []string, input *os.File, output, errorsOut io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	terminal := &Terminal{Input: input, Output: output, Reader: bufio.NewReader(input), Ctx: ctx}
	if terminal.Interactive() {
		if state, e := term.GetState(int(input.Fd())); e == nil {
			defer term.Restore(int(input.Fd()), state)
		}
	}
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("capsula", flag.ContinueOnError)
	fs.SetOutput(errorsOut)
	data := fs.String("data-dir", filepath.Join(home, "Capsula"), "каталог приватных данных")
	device := fs.String("device", "", "идентификатор собственной Капсулы")
	wait := fs.Int("wait", 180, "ожидание USB, секунды")
	mode := fs.String("mode", "simple", "simple | fast | expert")
	host := fs.String("host", "", "IP или hostname Капсулы")
	port := fs.Int("port", 22, "порт SSH")
	level := fs.String("level", "full", "уровень verify: basic | full")
	offline := fs.Bool("offline", false, "проверить комплект без USB/SSH")
	rescan := fs.Bool("rescan", false, "заново определить карту и выполнить RO content scan")
	jsonOut := fs.Bool("json", false, "структурированный результат")
	verbose := fs.Bool("verbose", false, "подробный ход операции")
	version := fs.Bool("version", false, "показать версию")
	var skips skipFlags
	fs.Var(&skips, "skip", "эксперт: пропустить этап (повторяемый; список через запятую)")
	fs.Usage = func() {
		fmt.Fprintln(errorsOut, "VK Капсула A113X — Go runtime без Python\nИспользование: capsula [параметры] diagnose|backup|root|update|verify|rollback|entware [параметры]\nБез команды — интерактивное меню. entware: status | install | remove\nЭтапы --skip:", strings.Join(Stages, ", "))
		fs.PrintDefaults()
	}
	command, action := "", "status"
	parseArgs := []string{}
	modeExplicit := false
	// The command may be before or after global options. Flag values are never
	// interpreted as commands (e.g. --data-dir root).
	valueFlags := map[string]bool{"--data-dir": true, "--device": true, "--wait": true, "--mode": true, "--skip": true, "--host": true, "--port": true, "--level": true, "-data-dir": true, "-device": true, "-wait": true, "-mode": true, "-skip": true, "-host": true, "-port": true, "-level": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--mode=") || a == "--mode" || a == "-mode" {
			modeExplicit = true
		}
		if strings.HasPrefix(a, "-") {
			parseArgs = append(parseArgs, a)
			if valueFlags[a] && i+1 < len(args) {
				i++
				parseArgs = append(parseArgs, args[i])
			}
			continue
		}
		if command == "" {
			command = a
		} else if command == "entware" && action == "status" {
			action = a
		} else {
			fmt.Fprintln(errorsOut, "Лишний аргумент:", a)
			return 2
		}
	}
	if e := fs.Parse(parseArgs); e != nil {
		if e == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *version {
		fmt.Fprintln(output, Version)
		return 0
	}
	resultOutput := output
	if *jsonOut {
		output = errorsOut
		terminal.Output = errorsOut
	}
	fail := func(e error) int {
		if errors.Is(e, context.Canceled) {
			fmt.Fprintln(errorsOut, "Сеанс прерван. Журналы сохранены; запись автоматически не повторяется.")
			return 130
		}
		fmt.Fprintln(errorsOut, "Остановлено:", e)
		return 1
	}
	if *wait < 1 {
		return fail(fmt.Errorf("--wait должен быть положительным"))
	}
	if *level != "basic" && *level != "full" {
		return fail(fmt.Errorf("неверный --level"))
	}
	if command == "" {
		if !terminal.Interactive() {
			fs.Usage()
			return 2
		}
		var e error
		command, action, e = terminal.Menu()
		if e != nil {
			return fail(e)
		}
		if command == "" {
			return 0
		}
	}
	if command == "root" || command == "update" || command == "rollback" {
		if !terminal.Interactive() {
			return fail(fmt.Errorf("установка требует интерактивного локального терминала"))
		}
		if !modeExplicit {
			fmt.Fprintln(output, "Режимы: 1. Простой — все проверки (по умолчанию)\n2. Быстрый — без бэкапа и полного аудита\n3. Эксперт — ручной выбор этапов, без гарантий")
			answer, e := terminal.Line("Режим [1]: ")
			if e != nil {
				return fail(e)
			}
			switch answer {
			case "", "1":
				*mode = "simple"
			case "2":
				*mode = "fast"
			case "3":
				*mode = "expert"
			default:
				return fail(fmt.Errorf("неверный режим"))
			}
		}
		if *mode == "expert" && len(skips) == 0 {
			fmt.Fprintln(output, ExpertWarning)
			for _, stage := range Stages {
				answer, e := terminal.Confirm("Пропустить " + stage + "?")
				if e != nil {
					return fail(e)
				}
				if answer {
					skips = append(skips, stage)
				}
			}
		}
	}
	policy, e := NewPolicy(*mode, skips)
	if e != nil {
		return fail(e)
	}

	if command == "root" || command == "update" || command == "rollback" {
		if e = terminal.ConfirmPolicy(policy); e != nil {
			return fail(e)
		}
	}
	r, e := LocateResources()
	if e != nil {
		return fail(e)
	}
	if command == "diagnose" && *offline {
		if e = r.Check(); e != nil {
			return fail(e)
		}
		if *jsonOut {
			_ = json.NewEncoder(resultOutput).Encode(map[string]any{"version": Version, "offline_only": true, "device_accessed": false, "resources_verified": true, "system_python_required": false})
		} else {
			fmt.Fprintln(output, "Комплект проверен. USB и SSH не использовались. Python не требуется.")
		}
		return 0
	}
	store, e := NewStore(filepath.Join(*data, "devices"))
	if e != nil {
		return fail(e)
	}
	if command == "verify" || command == "entware" {
		id, e := ChooseDevice(store, *device)
		if e != nil {
			return fail(e)
		}
		if *host == "" {
			if !terminal.Interactive() {
				return fail(fmt.Errorf("укажите --host"))
			}
			*host, e = terminal.Line("IP или hostname Капсулы: ")
			if e != nil {
				return fail(e)
			}
		}
		pw, e := terminal.Password(false)
		if e != nil {
			return fail(e)
		}
		defer clear(pw)
		if command == "verify" {
			report, e := SSHOperation(ctx, store, id, *host, *port, *level, pw)
			if *jsonOut {
				_ = json.NewEncoder(resultOutput).Encode(report)
			}
			if e != nil {
				if report.Root {
					fmt.Fprintln(output, "SSH root работает; расширенная проверка не пройдена.")
				}
				return fail(e)
			}
			fmt.Fprintln(output, "Проверка SSH пройдена (уровень "+*level+").")
			return 0
		}
		if action != "status" && action != "install" && action != "remove" {
			return fail(fmt.Errorf("неверная команда Entware"))
		}
		devicePath, _ := store.Device(id)
		unlock, e := store.Lock(id)
		if e != nil {
			return fail(e)
		}
		defer unlock()
		var installed Installed
		if e = ReadSealed(filepath.Join(devicePath, "installed.json"), &installed); e != nil {
			return fail(e)
		}
		if installed.State != "active" || installed.Identity != id {
			return fail(fmt.Errorf("нет активного пакета"))
		}
		work, e := store.Run(id, "entware")
		if e != nil {
			return fail(e)
		}
		client, e := dialSSH(ctx, *host, *port, installed.PublicKey, pw, work)
		if e != nil {
			return fail(e)
		}
		defer client.Close()
		client.Timeout = 900 * time.Second
		if action == "install" {
			fmt.Fprintln(output, "Установка Entware · загрузка и настройка пакетов могут занять несколько минут.")
		}
		body, e := client.Run("/usr/lib/capsula-root/entware "+action, false)
		if *jsonOut {
			_ = json.NewEncoder(resultOutput).Encode(map[string]any{"operation": "entware", "action": action, "success": e == nil, "output": string(body), "run": work})
		}
		if e != nil {
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			if len(lines) > 8 {
				lines = lines[len(lines)-8:]
			}
			fmt.Fprintln(errorsOut, strings.Join(lines, "\n"))
			fmt.Fprintln(errorsOut, "Приватный журнал:", work)
			return fail(e)
		}
		if *verbose || action == "status" {
			fmt.Fprint(output, string(body))
		} else {
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			if len(lines) > 0 {
				fmt.Fprintln(output, lines[len(lines)-1])
			}
		}
		return 0
	}
	display := &progressDisplay{writer: output, tty: outputTTY(output), verbose: *verbose}
	defer display.endLine()
	backend := &Backend{Ctx: ctx, Store: store, Resources: r, Policy: policy, ExpectedIdentity: *device, Wait: time.Duration(*wait) * time.Second, Password: func() ([]byte, error) { display.endLine(); return terminal.Password(true) }, Notify: display.notify, Progress: display.event, Reconnect: func(s string) error { display.endLine(); return terminal.Reconnect(s) }, BeforeWrite: func(id, op string, p Policy) error { display.endLine(); return terminal.BeforeWrite(id, op, p) }}
	if command == "root" {
		fmt.Fprintln(output, "Первая установка на Капсулу A113X. Штатные функции и данные сохраняются.")
	}
	out, e := backend.Execute(command, *rescan)
	if e != nil {
		display.endLine()
		if out != nil {
			fmt.Fprintln(errorsOut, "Приватный журнал:", out.Run)
		}
		if *jsonOut && out != nil {
			_ = json.NewEncoder(resultOutput).Encode(out)
		}
		return fail(e)
	}
	if out.InstallationCompleted {
		if e = terminal.AfterInstall(ctx, store, out); e != nil {
			return fail(e)
		}
		verb := "Установка"
		if out.Operation == "update" {
			verb = "Обновление"
		}
		if out.Version != "" {
			if out.Operation == "update" {
				fmt.Fprintf(output, "\nОбновление до версии %s завершено.\n", out.Version)
			} else {
				fmt.Fprintf(output, "\nУстановка версии %s завершена.\n", out.Version)
			}
		} else {
			ending := "завершена"
			if out.Operation == "update" {
				ending = "завершено"
			}
			fmt.Fprintf(output, "\n%s %s. Номер версии отсутствует в манифесте пакета.\n", verb, ending)
		}
		if out.SSHFullVerified {
			fmt.Fprintln(output, "Root SSH и полная проверка среды: пройдены.")
		} else if out.SSHRootVerified {
			fmt.Fprintln(output, "Root SSH работает; полная проверка среды не завершена.")
		} else {
			fmt.Fprintln(output, "Проверка SSH пропущена или не завершена; установка сохранена.")
		}
		fmt.Fprintln(output, "Работа утилиты завершена. Терминал можно закрыть.")
	} else if out.StorageClean {
		fmt.Fprintln(output, "Откат завершён. Отключите USB, подключите штатный БП и дождитесь загрузки.\nРабота утилиты завершена. Терминал можно закрыть.")
	} else {
		fmt.Fprintln(output, "Диагностика/бэкап завершены. Приватный журнал:", out.Run)
	}
	if *jsonOut {
		_ = json.NewEncoder(resultOutput).Encode(out)
	}
	return 0
}
