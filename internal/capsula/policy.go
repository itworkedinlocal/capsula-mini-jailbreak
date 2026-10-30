package capsula

import (
	"fmt"
	"sort"
	"strings"
)

const Version = "0.3.2"

var Stages = []string{"backup", "full-scan", "ecc-compare", "mapping-compare", "data-compare", "probe", "probe-audit", "stock-compare", "package-hash", "space", "conflicts", "post-verify", "ssh"}

const ExpertWarning = `ЭКСПЕРТНЫЙ РЕЖИМ: МОЖНО ПОЛУЧИТЬ НЕРАБОЧУЮ КОЛОНКУ И ПОТЕРЯТЬ ВСЕ ДАННЫЕ.
Этот режим позволяет отключить проверки, которые защищают от ошибочной записи.
Утилита выполнит выбранные действия, даже если результат окажется неработоспособным.
Восстановление из этой программы не гарантируется; может потребоваться ручное
восстановление или ремонт. Готовой кнопки «отменить» может не быть.
Если вы не знаете, как восстановить NAND и загрузку без этой утилиты,
выберите простой режим. Просмотр ролика и мысль «разберусь по ходу» не помогут
восстановить неработающую колонку. Не включайте этот режим из любопытства
или ради скорости: для ускорения есть быстрый режим.`

type Policy struct {
	Mode string   `json:"mode"`
	Skip []string `json:"skip"`
}

func NewPolicy(mode string, skips []string) (Policy, error) {
	p := Policy{Mode: mode, Skip: []string{}}
	if mode != "simple" && mode != "fast" && mode != "expert" {
		return p, fmt.Errorf("неизвестный режим %q", mode)
	}
	if mode != "expert" && len(skips) != 0 {
		return p, fmt.Errorf("--skip разрешён только в экспертном режиме")
	}
	if mode == "fast" {
		skips = []string{"backup", "full-scan", "ecc-compare", "mapping-compare", "data-compare", "probe", "probe-audit"}
	}
	seen := map[string]bool{}
	for _, group := range skips {
		for _, s := range strings.Split(group, ",") {
			found := false
			for _, allowed := range Stages {
				if s == allowed {
					found = true
				}
			}
			if !found {
				return p, fmt.Errorf("неизвестный этап %q; доступны: %s", s, strings.Join(Stages, ", "))
			}
			seen[s] = true
		}
	}
	// Comparisons require the snapshots they describe. Never synthesize evidence.
	if seen["backup"] {
		seen["mapping-compare"] = true
	}
	if seen["full-scan"] {
		seen["mapping-compare"] = true
	}
	if seen["probe"] {
		seen["probe-audit"] = true
	}
	if seen["post-verify"] {
		seen["probe-audit"] = true
	}
	for s := range seen {
		p.Skip = append(p.Skip, s)
	}
	sort.Strings(p.Skip)
	return p, nil
}

func (p Policy) Enabled(stage string) bool {
	for _, s := range p.Skip {
		if s == stage {
			return false
		}
	}
	return true
}
func (p Policy) Validate() error {
	q, e := NewPolicy(p.Mode, p.Skip)
	if p.Mode == "fast" {
		q, e = NewPolicy("fast", nil)
	}
	if e != nil {
		return e
	}
	if strings.Join(q.Skip, ",") != strings.Join(p.Skip, ",") {
		return fmt.Errorf("неполная/неупорядоченная политика")
	}
	return nil
}
func (p Policy) Shell() string {
	s := "CAPSULA_MODE=" + p.Mode + "\n"
	for _, stage := range Stages {
		n := "1"
		if !p.Enabled(stage) {
			n = "0"
		}
		s += "CHECK_" + strings.ToUpper(strings.ReplaceAll(stage, "-", "_")) + "=" + n + "\n"
	}
	return s
}

type StageResult struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type Outcome struct {
	Version               string                 `json:"installed_version,omitempty"`
	Identity              string                 `json:"identity,omitempty"`
	Operation             string                 `json:"operation"`
	Run                   string                 `json:"run"`
	Policy                Policy                 `json:"policy"`
	Stages                map[string]StageResult `json:"stages"`
	StorageClean          bool                   `json:"storage_clean"`
	InstallationCompleted bool                   `json:"installation_completed"`
	SSHRootVerified       bool                   `json:"ssh_root_verified"`
	SSHFullVerified       bool                   `json:"ssh_full_verified"`
	Error                 string                 `json:"error,omitempty"`
}

func NewOutcome(op string, p Policy) *Outcome {
	o := &Outcome{Operation: op, Policy: p, Stages: map[string]StageResult{}}
	for _, s := range Stages {
		state := "pending"
		if !p.Enabled(s) {
			state = "skipped"
		}
		o.Stages[s] = StageResult{Status: state}
	}
	return o
}
