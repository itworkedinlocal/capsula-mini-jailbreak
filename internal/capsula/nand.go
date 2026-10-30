package capsula

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sort"
	"strings"

	"github.com/u-root/u-root/pkg/dt"
)

const Erase = int64(131072)

var NormalNames = []string{"tpl", "misc", "boot_a", "boot_b", "system_a", "system_b", "data"}
var Reserved = map[string][2]int64{"bbt": {0x280000, 0x80000}, "env": {0x300000, 0x100000}, "keys": {0x400000, 0x100000}, "dtbrsv": {0x500000, 0x80000}, "ddr": {0x580000, 0x40000}}

type Geometry struct {
	Size  int64 `json:"size"`
	Erase int64 `json:"erasesize"`
	Write int64 `json:"writesize"`
	OOB   int64 `json:"oobsize"`
}

func (g Geometry) Validate() error {
	if g.Erase != Erase || g.Write != 2048 || g.OOB != 64 || g.Size < 0x8000000 || g.Size > 0x80000000 || g.Size%Erase != 0 {
		return fmt.Errorf("неподдерживаемая геометрия NAND/ECC: %+v", g)
	}
	return nil
}

type Partition struct {
	Name    string `json:"name"`
	Offset  int64  `json:"offset"`
	Size    int64  `json:"size"`
	Logical int64  `json:"logical_size"`
}
type Profile struct {
	Identity string      `json:"identity"`
	Geometry Geometry    `json:"geometry"`
	Bad      []int       `json:"bad_blocks"`
	Parts    []Partition `json:"partitions"`
	Layout   string      `json:"layout_signature"`
}

func (p Profile) Part(name string) (Partition, error) {
	for _, v := range p.Parts {
		if v.Name == name {
			return v, nil
		}
	}
	return Partition{}, fmt.Errorf("нет раздела %s", name)
}
func (p Profile) Validate() error {
	if e := p.Geometry.Validate(); e != nil {
		return e
	}
	if !digestRE.MatchString(p.Identity) || !digestRE.MatchString(p.Layout) {
		return fmt.Errorf("неверная идентичность/разметка профиля")
	}
	names := append([]string{"bootloader", "reserved"}, NormalNames...)
	if len(p.Parts) != len(names) {
		return fmt.Errorf("неподдерживаемая таблица разделов")
	}
	bad := map[int]bool{}
	for i, b := range p.Bad {
		if b < 0 || int64(b) >= p.Geometry.Size/Erase || (i > 0 && p.Bad[i-1] >= b) {
			return fmt.Errorf("неверная bad-block карта")
		}
		bad[b] = true
	}
	end := int64(0)
	for i, v := range p.Parts {
		if v.Name != names[i] || v.Offset != end || v.Size <= 0 || v.Size%Erase != 0 {
			return fmt.Errorf("неверные границы раздела %s", v.Name)
		}
		end += v.Size
		if i >= 2 {
			good := int64(0)
			for n := v.Offset / Erase; n < end/Erase; n++ {
				if !bad[int(n)] {
					good += Erase
				}
			}
			if v.Logical != good {
				return fmt.Errorf("неверный логический размер %s", v.Name)
			}
		}
	}
	if end != p.Geometry.Size {
		return fmt.Errorf("профиль не покрывает NAND")
	}
	return nil
}

type Layout struct {
	Sizes     map[string]int64 `json:"sizes"`
	Signature string           `json:"signature"`
}

func ReadTree(b []byte) (*dt.FDT, error) {
	if len(b) < 40 || len(b) > 1<<20 {
		return nil, fmt.Errorf("неверный размер DTB")
	}
	word := func(n int) uint64 { return uint64(binary.BigEndian.Uint32(b[n:])) }
	total := word(4)
	if word(0) != 0xd00dfeed || total != uint64(len(b)) || word(20) != 17 || word(8) < 40 || word(12) < 40 || word(16) < 40 || word(8)+word(36) > total || word(12)+word(32) > total {
		return nil, fmt.Errorf("неверные границы DTB")
	}
	t, e := dt.ReadFDT(bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	var visit func(*dt.Node, string) error
	visit = func(n *dt.Node, p string) error {
		if strings.Contains(n.Name, "/") {
			return fmt.Errorf("некорректное имя DTB")
		}
		if p == "" {
			p = "/"
		} else {
			p = strings.TrimRight(p, "/") + "/" + n.Name
		}
		if seen[p] {
			return fmt.Errorf("повторный узел DTB")
		}
		seen[p] = true
		props := map[string]bool{}
		for _, v := range n.Properties {
			if props[v.Name] {
				return fmt.Errorf("повторное свойство DTB")
			}
			props[v.Name] = true
		}
		for _, c := range n.Children {
			if e := visit(c, p); e != nil {
				return e
			}
		}
		return nil
	}
	return t, visit(t.RootNode, "")
}
func prop(n *dt.Node, key string) []byte {
	for _, p := range n.Properties {
		if p.Name == key {
			return p.Value
		}
	}
	return nil
}
func integer(b []byte) int64 {
	if len(b) == 4 {
		return int64(binary.BigEndian.Uint32(b))
	}
	if len(b) == 8 {
		return int64(binary.BigEndian.Uint64(b))
	}
	return -2
}
func LayoutFromTree(t *dt.FDT) (Layout, error) {
	var out Layout
	compatible := bytes.ToLower(prop(t.RootNode, "compatible"))
	if !bytes.Contains(compatible, []byte("amlogic")) || (!bytes.Contains(compatible, []byte("axg")) && !bytes.Contains(compatible, []byte("a113"))) {
		return out, fmt.Errorf("DTB не подтверждает A113X/AXG")
	}
	nodes, _ := t.RootNode.FindAll(func(n *dt.Node) bool { return bytes.Contains(prop(n, "compatible"), []byte("aml_mtd_nand")) })
	if len(nodes) != 1 || integer(prop(nodes[0], "fip_size")) != 0x200000 {
		return out, fmt.Errorf("неизвестный NAND controller/fip_size")
	}
	part, ok := nodes[0].LookupChildByName("nand_partition")
	if !ok {
		return out, fmt.Errorf("нет таблицы NAND")
	}
	out.Sizes = map[string]int64{}
	for _, name := range NormalNames {
		n, ok := part.LookupChildByName(name)
		if !ok {
			return out, fmt.Errorf("нет DTB раздела %s", name)
		}
		offset := integer(prop(n, "offset"))
		if offset != 0 && offset != -1 {
			return out, fmt.Errorf("неподдерживаемое явное смещение %s", name)
		}
		out.Sizes[name] = integer(prop(n, "size"))
	}
	if out.Sizes["tpl"] != 0 || out.Sizes["data"] != 0 {
		return out, fmt.Errorf("неизвестные размеры tpl/data")
	}
	out.Sizes["tpl"] = 0x800000
	for _, name := range NormalNames[:len(NormalNames)-1] {
		if out.Sizes[name] <= 0 || out.Sizes[name]%Erase != 0 {
			return out, fmt.Errorf("неверный размер %s", name)
		}
	}
	b, _ := Canonical(out.Sizes)
	out.Signature = SHA(b)
	return out, nil
}
func PhysicalProfile(id string, g Geometry, bad []int, l Layout) (Profile, error) {
	p := Profile{Identity: id, Geometry: g, Bad: append([]int{}, bad...), Layout: l.Signature}
	if e := g.Validate(); e != nil {
		return p, e
	}
	p.Parts = []Partition{{"bootloader", 0, 0x200000, 0x200000}, {"reserved", 0x200000, 0x600000, 0x600000}}
	set := map[int]bool{}
	for _, n := range bad {
		set[n] = true
	}
	cursor, last := int64(64), g.Size/Erase
	for _, name := range NormalNames {
		begin := cursor
		good := int64(0)
		if name == "data" {
			for cursor < last {
				if !set[int(cursor)] {
					good++
				}
				cursor++
			}
		} else {
			wanted := l.Sizes[name] / Erase
			for good < wanted && cursor < last {
				if !set[int(cursor)] {
					good++
				}
				cursor++
			}
			if good != wanted {
				return p, fmt.Errorf("разделы не помещаются в NAND")
			}
		}
		p.Parts = append(p.Parts, Partition{name, begin * Erase, (cursor - begin) * Erase, good * Erase})
	}
	return p, p.Validate()
}

type Block struct {
	Kind      string  `json:"kind"`
	Number    int     `json:"block"`
	Bad       *bool   `json:"bad"`
	Corrected *uint32 `json:"corrected"`
	Failed    *uint32 `json:"failed"`
	SHA       string  `json:"sha256"`
}
type Scan struct {
	Geometry Geometry `json:"geometry"`
	Bad      []int    `json:"bad_blocks"`
	Blocks   []Block  `json:"blocks"`
}

func ParseScan(body string, full bool) (Scan, error) {
	var s Scan
	s.Bad = []int{}
	scan := bufio.NewScanner(strings.NewReader(body))
	scan.Buffer(make([]byte, 4096), 1<<20)
	var rows []json.RawMessage
	for scan.Scan() {
		if len(bytes.TrimSpace(scan.Bytes())) > 0 {
			var v json.RawMessage
			if e := json.Unmarshal(scan.Bytes(), &v); e != nil {
				return s, fmt.Errorf("повреждён отчёт NAND: %w", e)
			}
			rows = append(rows, append([]byte{}, v...))
		}
	}
	if e := scan.Err(); e != nil {
		return s, e
	}
	if len(rows) < 2 {
		return s, fmt.Errorf("неполный отчёт NAND")
	}
	var first struct {
		Kind string `json:"kind"`
		Geometry
	}
	var last struct {
		Kind  string `json:"kind"`
		Mode  string `json:"mode"`
		Count int    `json:"blocks"`
	}
	if e := json.Unmarshal(rows[0], &first); e != nil {
		return s, e
	}
	if e := json.Unmarshal(rows[len(rows)-1], &last); e != nil {
		return s, e
	}
	mode := "metadata"
	if full {
		mode = "scan"
	}
	if first.Kind != "geometry" || last.Kind != "end" || last.Mode != mode {
		return s, fmt.Errorf("неверные границы/режим NAND отчёта")
	}
	s.Geometry = first.Geometry
	if e := s.Geometry.Validate(); e != nil {
		return s, e
	}
	if len(rows)-2 != int(s.Geometry.Size/Erase) || last.Count != len(rows)-2 {
		return s, fmt.Errorf("не обследованы все блоки NAND")
	}
	for i, row := range rows[1 : len(rows)-1] {
		var b Block
		if e := json.Unmarshal(row, &b); e != nil {
			return s, e
		}
		if b.Kind != "block" || b.Number != i || b.Bad == nil {
			return s, fmt.Errorf("повреждена bad-block карта")
		}
		if *b.Bad {
			s.Bad = append(s.Bad, i)
		} else if full && i >= 64 {
			if b.Corrected == nil || b.Failed == nil || *b.Failed != 0 || !digestRE.MatchString(b.SHA) {
				return s, fmt.Errorf("неисправимая ECC-ошибка/нет hash блока %d", i)
			}
		}
		s.Blocks = append(s.Blocks, b)
	}
	return s, nil
}
func CheckMetadata(p Profile, s Scan, l Layout) error {
	if p.Geometry != s.Geometry || p.Layout != l.Signature || !equalInts(p.Bad, s.Bad) {
		return fmt.Errorf("геометрия, bad blocks или разметка изменились")
	}
	return nil
}
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func CompareECC(a, b string, size int64) (string, error) {
	for _, p := range []string{a, b} {
		i, e := os.Stat(p)
		if e != nil {
			return "", e
		}
		if i.Size() != size {
			return "", fmt.Errorf("укороченное ECC-чтение")
		}
	}
	x, e := FileSHA(a)
	if e != nil {
		return "", e
	}
	y, e := FileSHA(b)
	if e != nil {
		return "", e
	}
	if x != y {
		return "", fmt.Errorf("ECC-исправленные чтения не совпали")
	}
	return x, nil
}
func VerifyMapping(p Profile, s Scan, files map[string]string) error {
	if e := p.Validate(); e != nil {
		return e
	}
	if p.Geometry != s.Geometry || !equalInts(p.Bad, s.Bad) || len(s.Blocks) != int(p.Geometry.Size/Erase) {
		return fmt.Errorf("профиль и скан относятся к разным состояниям")
	}
	buf := make([]byte, Erase)
	for _, part := range p.Parts[2:] {
		f, e := os.Open(files[part.Name])
		if e != nil {
			return e
		}
		for n := part.Offset / Erase; n < (part.Offset+part.Size)/Erase; n++ {
			row := s.Blocks[n]
			if row.Bad != nil && *row.Bad {
				continue
			}
			_, e = io.ReadFull(f, buf)
			if e != nil || SHA(buf) != row.SHA {
				f.Close()
				return fmt.Errorf("ECC-чтение не совпало: %s, физический блок %d, offset %#x; сравните epoch чтений", part.Name, n, n*Erase)
			}
		}
		var extra [1]byte
		n, e := f.Read(extra[:])
		f.Close()
		if n != 0 || e != io.EOF {
			return fmt.Errorf("лишние данные раздела %s", part.Name)
		}
	}
	return nil
}
func CompareRaw(a, b string, size int64) (map[string]any, error) {
	x, e := os.Open(a)
	if e != nil {
		return nil, e
	}
	defer x.Close()
	y, e := os.Open(b)
	if e != nil {
		return nil, e
	}
	defer y.Close()
	for _, f := range []*os.File{x, y} {
		i, e := f.Stat()
		if e != nil {
			return nil, e
		}
		if i.Size() != size {
			return nil, fmt.Errorf("укороченный RAW/OOB")
		}
	}
	u, v := make([]byte, 1<<20), make([]byte, 1<<20)
	var changed, count int64
	for {
		n, e := x.Read(u)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if _, e = io.ReadFull(y, v[:n]); e != nil {
			return nil, e
		}
		if !bytes.Equal(u[:n], v[:n]) {
			for i := 0; i < n; i++ {
				if u[i] != v[i] {
					changed++
					count += int64(bits.OnesCount8(u[i] ^ v[i]))
				}
			}
		}
	}
	ha, e := FileSHA(a)
	if e != nil {
		return nil, e
	}
	hb, e := FileSHA(b)
	return map[string]any{"bytes": size, "sha256": []string{ha, hb}, "raw_byte_identical": changed == 0, "changed_bytes": changed, "changed_bits": count, "blocks_installation": false}, e
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
