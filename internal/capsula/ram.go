package capsula

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/u-root/u-root/pkg/cpio"
	"github.com/u-root/u-root/pkg/dt"
)

type Asset struct {
	Path    string
	Address uint32
}
type RAMBundle struct {
	Assets []Asset
	Words  []string
	Nonce  string
}
type RAMOptions struct {
	Operation string
	Profile   *Profile
	Slot      string
	Writable  bool
	Expected  string
	Token     string
	Package   string
	Policy    Policy
}

func DeviceConfig(p Profile, slot string, writable bool) (string, error) {
	if e := p.Validate(); e != nil {
		return "", e
	}
	if slot != "a" && slot != "b" {
		return "", fmt.Errorf("неизвестный слот")
	}
	data, stock := -1, -1
	for i, v := range p.Parts {
		if v.Name == "data" {
			data = i
		}
		if v.Name == "system_"+slot {
			stock = i
		}
	}
	if data < 0 || stock < 0 {
		return "", fmt.Errorf("нет data/stock")
	}
	w := 0
	if writable {
		w = 1
	}
	return fmt.Sprintf("DATA_INDEX=%d\nDATA_SIZE=%d\nSTOCK_INDEX=%d\nSTOCK_SIZE=%d\nSTOCK_NAME=system_%s\nMTD_COUNT=%d\nDATA_WRITABLE=%d\n", data, p.Parts[data].Size, stock, p.Parts[stock].Size, slot, len(p.Parts), w), nil
}
func DeviceTree(r Resources, p *Profile, writable bool) (*dt.FDT, error) {
	b, e := os.ReadFile(r.RAM("vk-mini-a113x-usb-only.dtb"))
	if e != nil {
		return nil, e
	}
	tree, e := ReadTree(b)
	if e != nil {
		return nil, e
	}
	nodes, _ := tree.RootNode.FindAll(func(n *dt.Node) bool { return n.Name == "nand-controller@7800" })
	if len(nodes) != 1 {
		return nil, fmt.Errorf("нет проверенного NAND controller")
	}
	controller := nodes[0]
	chip, ok := controller.LookupChildByName("nand@0")
	if !ok {
		return nil, fmt.Errorf("нет nand@0")
	}
	if _, ok = chip.LookProperty("nand-on-flash-bbt"); ok {
		return nil, fmt.Errorf("on-flash BBT запрещена")
	}
	if integer(prop(chip, "nand-ecc-strength")) != 8 || integer(prop(chip, "nand-ecc-step-size")) != 512 {
		return nil, fmt.Errorf("непроверенный NAND ECC")
	}
	controller.Update(dt.PropertyString("status", "okay"))
	partitions, ok := chip.LookupChildByName("partitions")
	if !ok {
		return nil, fmt.Errorf("нет fixed partitions")
	}
	partitions.Children = nil
	parts := []Partition{{Name: "capsula-scan"}}
	if p != nil {
		if e = p.Validate(); e != nil {
			return nil, e
		}
		parts = p.Parts
	}
	for _, part := range parts {
		reg := make([]byte, 8)
		binary.BigEndian.PutUint32(reg, uint32(part.Offset))
		binary.BigEndian.PutUint32(reg[4:], uint32(part.Size))
		node := dt.NewNode(fmt.Sprintf("partition@%x", part.Offset), dt.WithProperty(dt.PropertyString("label", part.Name), dt.Property{Name: "reg", Value: reg}))
		if part.Name != "data" || !writable {
			node.Properties = append(node.Properties, dt.Property{Name: "read-only"})
		}
		partitions.Children = append(partitions.Children, node)
	}
	return tree, nil
}
func BuildRAM(r Resources, folder string, o RAMOptions) (RAMBundle, error) {
	var result RAMBundle
	if e := o.Policy.Validate(); e != nil {
		return result, e
	}

	if e := r.Check(); e != nil {
		return result, e
	}
	if e := PrivateDir(folder); e != nil {
		return result, e
	}
	tree, e := DeviceTree(r, o.Profile, o.Writable)
	if e != nil {
		return result, e
	}
	var dtb bytes.Buffer
	if _, e = tree.Write(&dtb); e != nil {
		return result, e
	}
	if e = writePrivateExclusive(filepath.Join(folder, "device.dtb"), dtb.Bytes()); e != nil {
		return result, e
	}
	compressed, e := os.ReadFile(r.RAM("initramfs.cpio.gz"))
	if e != nil {
		return result, e
	}
	gz, e := gzip.NewReader(bytes.NewReader(compressed))
	if e != nil {
		return result, e
	}
	base, e := io.ReadAll(io.LimitReader(gz, 64<<20))
	gz.Close()
	if e != nil {
		return result, e
	}
	records := map[string]cpio.Record{}
	reader := cpio.Newc.Reader(bytes.NewReader(base))
	for {
		rec, e := reader.ReadRecord()
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, e
		}
		if _, exists := records[rec.Name]; exists {
			return result, fmt.Errorf("повторный CPIO member")
		}
		records[rec.Name] = rec
	}
	delete(records, "capsula-ram-init")
	delete(records, cpio.Trailer)
	put := func(name string, content []byte, mode uint64) {
		records[name] = cpio.StaticRecord(content, cpio.Info{Name: name, Mode: mode, NLink: 1})
	}
	init, e := os.ReadFile(r.RAM("init"))
	if e != nil {
		return result, e
	}
	start, end := bytes.Index(init, []byte("check_storage() {")), bytes.Index(init, []byte("check_storage\n"))
	if start < 0 || end < start {
		return result, fmt.Errorf("неизвестный RAM init")
	}
	parts := []Partition{{Name: "capsula-scan"}}
	if o.Profile != nil {
		parts = o.Profile.Parts
	}
	var check strings.Builder
	check.WriteString("check_storage() {\n")
	for i, p := range parts {
		flags := 0
		if o.Writable && p.Name == "data" {
			flags = 1024
		}
		fmt.Fprintf(&check, "[ \"$(cat /sys/class/mtd/mtd%d/name)\" = %s ] || stop_test mtd_name\nflags=$(cat /sys/class/mtd/mtd%d/flags)\n[ \"$((flags & 1024))\" = %d ] || stop_test mtd_write_permission\n[ \"$(cat /sys/class/mtd/mtd%d/erasesize)\" = 131072 ] || stop_test erase_size\n[ \"$(cat /sys/class/mtd/mtd%d/writesize)\" = 2048 ] || stop_test write_size\n", i, p.Name, i, flags, i, i)
		if o.Profile != nil {
			fmt.Fprintf(&check, "[ \"$(cat /sys/class/mtd/mtd%d/size)\" = %d ] || stop_test mtd_size\n", i, p.Size)
		}
	}
	fmt.Fprintf(&check, "[ ! -e /sys/class/mtd/mtd%d ] || stop_test extra_mtd\n}\n", len(parts))
	newInit := append(bytes.Clone(init[:start]), []byte(check.String())...)
	newInit = append(newInit, init[end:]...)
	put("capsula-agent-init", newInit, cpio.S_IFREG|0755)
	nonce := RandomHex(32)
	put("capsula-run-id", []byte(nonce+"\n"), cpio.S_IFREG|0600)
	for _, name := range []string{"nand-agent", "ubi-control", "directory-times", "ram-restart"} {
		b, e := os.ReadFile(r.Stock("bin/aarch64/" + name))
		if e != nil {
			return result, e
		}
		put("capsula-"+name, b, cpio.S_IFREG|0755)
	}
	put("capsula-policy.conf", []byte(o.Policy.Shell()), cpio.S_IFREG|0600)
	policy, e := os.ReadFile(r.Stock("runtime-policy"))
	if e != nil {
		return result, e
	}
	put("capsula-runtime-policy", policy, cpio.S_IFREG|0644)
	if o.Profile != nil {
		config, e := DeviceConfig(*o.Profile, o.Slot, o.Writable)
		if e != nil {
			return result, e
		}
		put("capsula-device.conf", []byte(config), cpio.S_IFREG|0600)
		for _, name := range []string{"data", "stock", "capsula-root-payload"} {
			put(name, nil, cpio.S_IFDIR|0700)
		}
		for _, name := range []string{"inspect-stock", "inspect-device"} {
			b, e := os.ReadFile(r.Stock(name))
			if e != nil {
				return result, e
			}
			put("capsula-"+name, b, cpio.S_IFREG|0755)
		}
		tool, e := os.ReadFile(r.Stock("toolkit/aarch64/busybox"))
		if e != nil {
			return result, e
		}
		put("busybox-capsula", tool, cpio.S_IFREG|0755)
	}
	if o.Profile != nil && o.Writable {
		if o.Policy.Enabled("data-compare") && !digestRE.MatchString(o.Expected) {
			return result, fmt.Errorf("нужен свежий снимок data")
		}
		if (o.Token != "" && !digestRE.MatchString(o.Token)) || (o.Policy.Enabled("probe") && o.Operation != "rollback" && o.Token == "") {
			return result, fmt.Errorf("нужен индивидуальный probe token")
		}
		if o.Token == "" {
			o.Token = RandomHex(32)
		}
		put("capsula-expected-data.sha256", []byte(o.Expected+"\n"), cpio.S_IFREG|0600)
		put("capsula-probe-id", []byte(o.Token+"\n"), cpio.S_IFREG|0600)

		read := []byte("#!/bin/sh\nset -eu\n. /capsula-device.conf\nexec /capsula-nand-agent read \"$DATA_INDEX\" \"$DATA_SIZE\" 1\n")
		put("capsula-read-data", read, cpio.S_IFREG|0755)
		for dest, src := range map[string]string{"capsula-control": "persist-control", "capsula-overlay-install": "overlay-install"} {
			b, e := os.ReadFile(r.Stock(src))
			if e != nil {
				return result, e
			}
			put(dest, b, cpio.S_IFREG|0755)
		}
		if o.Package != "" {
			if _, e = ValidatePackage(o.Package, o.Profile.Identity, o.Policy.Enabled("package-hash")); e != nil {
				return result, e
			}
			for _, name := range []string{"overlay-files.tar", "manifest.json", "files.sha256", "files.tsv", "lower.sha256", "payload-bytes"} {
				b, e := os.ReadFile(filepath.Join(o.Package, name))
				if e != nil {
					return result, e
				}
				put("capsula-root-payload/"+name, b, cpio.S_IFREG|0600)
			}
		}
	}
	var archive bytes.Buffer
	writer := cpio.Newc.Writer(&archive)
	for _, name := range sortedKeys(records) {
		if e = writer.WriteRecord(records[name]); e != nil {
			return result, e
		}
	}
	if e = cpio.WriteTrailer(writer); e != nil {
		return result, e
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, e = zw.Write(archive.Bytes()); e != nil {
		return result, e
	}
	if e = zw.Close(); e != nil {
		return result, e
	}
	payload := out.Bytes()
	header := make([]byte, 64)
	binary.BigEndian.PutUint32(header, 0x27051956)
	binary.BigEndian.PutUint32(header[12:], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[24:], crc32.ChecksumIEEE(payload))
	copy(header[28:], []byte{5, 22, 3, 1})
	copy(header[32:], []byte("Capsula device-specific Go RAM"))
	binary.BigEndian.PutUint32(header[4:], crc32.ChecksumIEEE(header))
	if e = writePrivateExclusive(filepath.Join(folder, "initramfs.uimg"), append(header, payload...)); e != nil {
		return result, e
	}
	result = RAMBundle{[]Asset{{r.RAM("Image"), 0x1080000}, {filepath.Join(folder, "device.dtb"), 0x1000000}, {filepath.Join(folder, "initramfs.uimg"), 0x4000000}}, strings.Fields("console=ttyAML0,115200n8 rdinit=/capsula-agent-init loglevel=4 panic=0 reboot=cold"), nonce}
	word := "capsula_nand_ro=1"
	if o.Profile != nil && o.Writable {
		word = "capsula_persist_install=1"
	}
	result.Words = append(result.Words, word)
	if e = ValidateRAM(r, result, o.Profile, o.Writable); e != nil {
		return result, e
	}
	err := AtomicJSON(filepath.Join(folder, "bundle.json"), map[string]any{"nonce": nonce, "writable": o.Writable, "policy": o.Policy, "files": map[string]string{"Image": KernelSHA, "device.dtb": SHA(dtb.Bytes()), "initramfs.uimg": SHA(append(header, payload...))}})
	return result, err
}
func ValidateRAM(r Resources, b RAMBundle, p *Profile, writable bool) error {
	if len(b.Assets) != 3 {
		return fmt.Errorf("неполный RAM bundle")
	}
	addresses := []uint32{0x1080000, 0x1000000, 0x4000000}
	var ends [][2]uint64
	for i, a := range b.Assets {
		if a.Address != addresses[i] {
			return fmt.Errorf("неверный RAM адрес")
		}
		body, e := os.ReadFile(a.Path)
		if e != nil {
			return e
		}
		length := uint64((len(body) + 2047) &^ 2047)
		if i == 0 {
			if SHA(body) != KernelSHA || len(body) < 64 {
				return fmt.Errorf("непроверенное RAM ядро")
			}
			length = max(length, binary.LittleEndian.Uint64(body[16:24]))
		}
		start := uint64(a.Address)
		end := start + length
		if start < 0x1000000 || end > 0x5000000 {
			return fmt.Errorf("RAM image вне проверенного окна")
		}
		for _, old := range ends {
			if start < old[1] && old[0] < end {
				return fmt.Errorf("RAM диапазоны пересекаются")
			}
		}
		ends = append(ends, [2]uint64{start, end})
	}
	data, e := os.ReadFile(b.Assets[1].Path)
	if e != nil {
		return e
	}
	actual, e := ReadTree(data)
	if e != nil {
		return e
	}
	expected, e := DeviceTree(r, p, writable)
	if e != nil {
		return e
	}
	if !sameNode(actual.RootNode, expected.RootNode) || fmt.Sprint(actual.ReserveEntries) != fmt.Sprint(expected.ReserveEntries) {
		return fmt.Errorf("DTB изменён за пределами разрешённых настроек")
	}
	image, e := os.ReadFile(b.Assets[2].Path)
	if e != nil {
		return e
	}
	if len(image) < 64 {
		return fmt.Errorf("короткий initrd")
	}
	h := bytes.Clone(image[:64])
	saved := binary.BigEndian.Uint32(h[4:])
	clear(h[4:8])
	if binary.BigEndian.Uint32(h) != 0x27051956 || saved != crc32.ChecksumIEEE(h) || int(binary.BigEndian.Uint32(h[12:])) != len(image)-64 || binary.BigEndian.Uint32(h[24:]) != crc32.ChecksumIEEE(image[64:]) {
		return fmt.Errorf("повреждён initrd CRC")
	}
	return nil
}

// Empty DT properties may be nil before serialization and []byte{} afterwards.
// Compare their bytes, not the Go slice representation.
func sameNode(a, b *dt.Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Name != b.Name || len(a.Properties) != len(b.Properties) || len(a.Children) != len(b.Children) {
		return false
	}
	for i, p := range a.Properties {
		q := b.Properties[i]
		if p.Name != q.Name || !bytes.Equal(p.Value, q.Value) {
			return false
		}
	}
	for i, n := range a.Children {
		if !sameNode(n, b.Children[i]) {
			return false
		}
	}
	return true
}
