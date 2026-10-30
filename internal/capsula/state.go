package capsula

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func SHA(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func FileSHA(name string) (string, error) {
	f, e := os.Open(name)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Canonical preserves Python's ensure_ascii=True JSON sealing used by v0.2.x.
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var n any
	if e = d.Decode(&n); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	var quoted = func(s string) {
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 32 || r >= 127 {
					if r > 0xffff {
						a, b := utf16.EncodeRune(r)
						fmt.Fprintf(&out, `\u%04x\u%04x`, a, b)
					} else {
						fmt.Fprintf(&out, `\u%04x`, r)
					}
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	}
	var emit func(any)
	emit = func(n any) {
		switch v := n.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case json.Number:
			out.WriteString(v.String())
		case string:
			quoted(v)
		case []any:
			out.WriteByte('[')
			for i, x := range v {
				if i > 0 {
					out.WriteByte(',')
				}
				emit(x)
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				quoted(k)
				out.WriteByte(':')
				emit(v[k])
			}
			out.WriteByte('}')
		}
	}
	emit(n)
	return out.Bytes(), nil
}

func PrivateDir(path string) error {
	path = filepath.Clean(path)
	if p, e := os.Lstat(path); e == nil {
		if !p.IsDir() || p.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("небезопасный приватный каталог: %s", path)
		}
		if e = owned(p); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		parent := filepath.Dir(path)
		if parent != path {
			if e = PrivateDirParent(parent); e != nil {
				return e
			}
		}
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
	}
	return protectDir(path)
}
func PrivateDirParent(path string) error {
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return PrivateDir(path)
	}
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("небезопасный родитель: %s", path)
	}
	return nil
}
func AtomicJSON(path string, v any) error {
	if e := PrivateDir(filepath.Dir(path)); e != nil {
		return e
	}
	if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state подменён ссылкой")
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return replaceState(tmp, path)
}
func ReadPrivate(path string, v any) error {
	f, e := openPrivate(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || !privatePermissions(info) || info.Size() > 16<<20 {
		return fmt.Errorf("небезопасное состояние: %s", path)
	}
	if e = owned(info); e != nil {
		return e
	}
	d := json.NewDecoder(io.LimitReader(f, 16<<20))
	if e = d.Decode(v); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("лишние данные JSON")
	}
	return nil
}
func SaveSealed(path string, v any) error {
	b, e := Canonical(v)
	if e != nil {
		return e
	}
	return AtomicJSON(path, map[string]any{"value": v, "sha256": SHA(b)})
}
func ReadSealed(path string, v any) error {
	var row struct {
		Value json.RawMessage `json:"value"`
		SHA   string          `json:"sha256"`
	}
	if e := ReadPrivate(path, &row); e != nil {
		return e
	}
	var obj any
	d := json.NewDecoder(bytes.NewReader(row.Value))
	d.UseNumber()
	if e := d.Decode(&obj); e != nil {
		return e
	}
	b, e := Canonical(obj)
	if e != nil {
		return e
	}
	if !digestRE.MatchString(row.SHA) || SHA(b) != row.SHA {
		return fmt.Errorf("контрольная сумма состояния не совпадает: %s", path)
	}
	return json.Unmarshal(row.Value, v)
}

type Store struct{ Root string }

func NewStore(root string) (*Store, error) {
	p, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	if e = PrivateDir(p); e != nil {
		return nil, e
	}
	return &Store{p}, nil
}
func (s *Store) Device(id string) (string, error) {
	if !digestRE.MatchString(id) {
		return "", fmt.Errorf("неверный идентификатор устройства")
	}
	p := filepath.Join(s.Root, id)
	return p, PrivateDir(p)
}
func (s *Store) Run(id, op string) (string, error) {
	d, e := s.Device(id)
	if e != nil {
		return "", e
	}
	if !regexp.MustCompile(`^[a-z-]+$`).MatchString(op) {
		return "", fmt.Errorf("неверная операция")
	}
	d = filepath.Join(d, "runs")
	if e = PrivateDir(d); e != nil {
		return "", e
	}
	return os.MkdirTemp(d, time.Now().Format("20060102-150405")+"-"+op+"-")
}
func (s *Store) Lock(id string) (func(), error) {
	d, e := s.Device(id)
	if e != nil {
		return nil, e
	}
	return lockFile(filepath.Join(d, "operation.lock"))
}
func Exists(p string) bool { _, e := os.Lstat(p); return e == nil }
func SafeJoin(base, rel string) (string, error) {
	if !safeRelativePath(rel) {
		return "", fmt.Errorf("небезопасный путь")
	}
	p := filepath.Join(base, filepath.FromSlash(rel))
	r, e := filepath.Rel(base, p)
	if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("путь вне каталога устройства")
	}
	for x := p; x != base; x = filepath.Dir(x) {
		if i, e := os.Lstat(x); e == nil && i.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("символическая ссылка в пути")
		}
	}
	return p, nil
}

type Artifact struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	SHA   string `json:"sha256"`
}

func Ref(base, path string) (Artifact, error) {
	rel, e := filepath.Rel(base, path)
	if e != nil {
		return Artifact{}, e
	}
	if _, e = SafeJoin(base, rel); e != nil {
		return Artifact{}, e
	}
	i, e := os.Stat(path)
	if e != nil {
		return Artifact{}, e
	}
	h, e := FileSHA(path)
	return Artifact{filepath.ToSlash(rel), i.Size(), h}, e
}
func ArtifactPath(base string, a Artifact) (string, error) {
	p, e := SafeJoin(base, a.Path)
	if e != nil {
		return "", e
	}
	i, e := os.Stat(p)
	if e != nil {
		return "", e
	}
	h, e := FileSHA(p)
	if e != nil {
		return "", e
	}
	if !i.Mode().IsRegular() || i.Size() != a.Bytes || h != a.SHA {
		return "", fmt.Errorf("сохранённый артефакт отсутствует/изменён: %s", a.Path)
	}
	return p, nil
}
