package capsula

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

type ProgressEvent struct {
	Stage   string
	Detail  string
	Current int
	Total   int
	Verbose bool
}

type progressDisplay struct {
	writer  io.Writer
	tty     bool
	verbose bool
	line    bool
	last    string
}

func outputTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "dumb"
}

func (p *progressDisplay) endLine() {
	if p.line {
		fmt.Fprintln(p.writer)
		p.line = false
	}
}

func (p *progressDisplay) event(e ProgressEvent) {
	if e.Verbose && !p.verbose {
		return
	}
	if e.Total > 0 {
		percent := e.Current * 100 / e.Total
		if p.tty {
			fmt.Fprintf(p.writer, "\r  %s: %3d%%", e.Detail, percent)
			p.line = true
		} else if percent == 100 || p.last != e.Stage {
			fmt.Fprintf(p.writer, "  %s: %d%%\n", e.Detail, percent)
		}
		p.last = e.Stage
		if percent == 100 {
			p.endLine()
		}
		return
	}
	p.endLine()
	if e.Stage != p.last || p.verbose {
		fmt.Fprintf(p.writer, "  • %s\n", e.Detail)
	}
	p.last = e.Stage
}

func (p *progressDisplay) notify(s string) {
	if strings.HasPrefix(s, "RAW/OOB: ") {
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(s, "RAW/OOB: "), "%"))
		if err == nil {
			p.event(ProgressEvent{Stage: "raw", Detail: "Чтение RAW/OOB", Current: n, Total: 100})
			return
		}
	}
	p.endLine()
	fmt.Fprintln(p.writer, s)
}

func (t *Terminal) menuTitle(title string) {
	if outputTTY(t.Output) && os.Getenv("NO_COLOR") == "" {
		fmt.Fprintf(t.Output, "\n\033[1;36mКапсула\033[0m · \033[1m%s\033[0m\n\n", title)
	} else {
		fmt.Fprintf(t.Output, "\nКапсула · %s\n\n", title)
	}
}

// Menus only select an action; they never touch USB, SSH or private device data.
func (t *Terminal) Menu() (command, action string, err error) {
	page := "main"
	for {
		switch page {
		case "main":
			t.menuTitle("Главное меню")
			fmt.Fprint(t.Output, "  1  Установить     Первый root SSH на стоковой колонке\n  2  Обновить       Обновить установленный джейлбрейк\n  3  Проверить      Проверить SSH и среду\n  4  Entware        Дополнительные пакеты\n  5  Обслуживание   Диагностика, бэкап и откат\n\n  0  Выход\n")
		case "service":
			t.menuTitle("Обслуживание")
			fmt.Fprint(t.Output, "  1  Диагностика    Проверить устройство\n  2  Полный бэкап   Сохранить копию NAND\n  3  Откат          Удалить джейлбрейк, вернуть штатные файлы\n\n  0  Назад\n")
		case "entware":
			t.menuTitle("Entware")
			fmt.Fprint(t.Output, "  1  Состояние     Проверить установку и /opt\n  2  Установить    Установить или завершить настройку\n  3  Отключить     Пакеты останутся на колонке\n\n  0  Назад\n")
		}
		answer, e := t.Line("Выберите пункт: ")
		if e != nil {
			return "", "", e
		}
		if answer == "0" {
			if page == "main" {
				return "", "", nil
			}
			page = "main"
			continue
		}
		switch page {
		case "main":
			if answer == "4" {
				page = "entware"
				continue
			}
			if answer == "5" {
				page = "service"
				continue
			}
			command = map[string]string{"1": "root", "2": "update", "3": "verify"}[answer]
		case "service":
			command = map[string]string{"1": "diagnose", "2": "backup", "3": "rollback"}[answer]
		case "entware":
			action = map[string]string{"1": "status", "2": "install", "3": "remove"}[answer]
			if action != "" {
				return "entware", action, nil
			}
		}
		if command != "" {
			return command, "status", nil
		}
		fmt.Fprintln(t.Output, "Такого пункта нет. Введите номер из меню.")
	}
}
