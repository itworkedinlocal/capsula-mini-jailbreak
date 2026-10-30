package capsula

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type wireRecord struct {
	Kind    string `json:"kind"`
	Type    int    `json:"type"`
	Request int    `json:"request"`
	Value   int    `json:"value"`
	Index   int    `json:"index"`
	Size    int    `json:"size"`
	Prefix  string `json:"prefix"`
}
type referenceWire struct {
	records    []wireRecord
	index, cut int
	err        error
}

func (w *referenceWire) exchange(kind string, typ, req, value, index int, b []byte) (int, error) {
	if w.cut > 0 && w.index+1 == w.cut {
		w.index++
		return 0, io.ErrUnexpectedEOF
	}
	if w.index >= len(w.records) {
		w.err = fmt.Errorf("unexpected extra transfer %s", kind)
		return 0, w.err
	}
	row := w.records[w.index]
	w.index++
	if row.Kind != kind || row.Type != typ || row.Request != req || row.Value != value || row.Index != index || row.Size != len(b) {
		w.err = fmt.Errorf("transfer %d mismatch: %+v, got %s %d/%d/%d/%d len%d", w.index, row, kind, typ, req, value, index, len(b))
		return 0, w.err
	}
	prefix, _ := hex.DecodeString(row.Prefix)
	if kind == "read" || (kind == "control" && typ&0x80 != 0) {
		clear(b)
		copy(b, prefix)
	} else if hex.EncodeToString(b[:min(len(b), 128)]) != row.Prefix {
		w.err = fmt.Errorf("transfer %d payload mismatch", w.index)
		return 0, w.err
	}
	return len(b), nil
}
func (w *referenceWire) Control(_ context.Context, typ, req byte, v, i uint16, b []byte) (int, error) {
	return w.exchange("control", int(typ), int(req), int(v), int(i), b)
}
func (w *referenceWire) Read(_ context.Context, b []byte) (int, error) {
	return w.exchange("read", 129, 0, 0, 0, b)
}
func (w *referenceWire) Write(_ context.Context, b []byte) (int, error) {
	return w.exchange("write", 2, 0, 0, 0, b)
}
func referenceRows(t *testing.T, name string) []wireRecord {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "usb", name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []wireRecord
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var r wireRecord
		if err = json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}
func referenceArgs(t *testing.T, name string) []string {
	t.Helper()
	switch name {
	case "identify":
		return []string{"identify", "7"}
	case "bulk":
		return []string{"bulkcmd", "echo priming"}
	case "read", "read-big", "store":
		kind, addr, size := "mem", "0x4000000", "0x800"
		if name == "store" {
			kind, addr = "store", "boot_a"
		}
		if name == "read-big" {
			size = "0x20800"
		}
		return []string{"mread", kind, addr, "normal", size, filepath.Join(t.TempDir(), "out")}
	default:
		n := 2048
		if name == "write-big" {
			n = 0x20800
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		p := filepath.Join(t.TempDir(), "chunk")
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return []string{"mwrite", p, "mem", "0x1080000", "normal"}
	}
}
func TestUSBProtocolMatchesPinnedHelper(t *testing.T) {
	for _, name := range []string{"identify", "bulk", "read", "read-big", "store", "write", "write-big"} {
		t.Run(name, func(t *testing.T) {
			w := &referenceWire{records: referenceRows(t, name)}
			args := referenceArgs(t, name)
			trace := &tracedUSBWire{usbWire: w}
			_, err := protocolCall(context.Background(), trace, args, false)
			if err != nil || w.err != nil || w.index != len(w.records) {
				t.Fatalf("err=%v wire=%v transfers=%d/%d", err, w.err, w.index, len(w.records))
			}
			if len(trace.rows) != len(w.records) {
				t.Fatal("incomplete transfer log")
			}
		})
	}
}

type fragmentWire struct {
	usbWire
	pending []byte
}

func (w *fragmentWire) Read(ctx context.Context, b []byte) (int, error) {
	if len(w.pending) > 0 {
		n := copy(b, w.pending)
		w.pending = w.pending[n:]
		return n, nil
	}
	n, err := w.usbWire.Read(ctx, b)
	if err == nil && n > 512 {
		half := n / 2
		w.pending = bytes.Clone(b[half:n])
		return half, nil
	}
	return n, err
}
func TestUSBReadAcceptsPartialPayloadTransfers(t *testing.T) {
	wire := &referenceWire{records: referenceRows(t, "read-big")}
	args := referenceArgs(t, "read-big")
	if _, err := protocolCall(context.Background(), &fragmentWire{usbWire: wire}, args, false); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(args[5])
	if err != nil || len(body) != 0x20800 || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("partial payload corrupted", err)
	}
	if wire.index != len(wire.records) {
		t.Fatal("incomplete reference exchange")
	}
}

type statusWire struct {
	reply string
	short bool
	reads int
}

func (w *statusWire) Control(_ context.Context, _ byte, _ byte, _ uint16, _ uint16, b []byte) (int, error) {
	if w.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (w *statusWire) Read(_ context.Context, b []byte) (int, error) {
	w.reads++
	return copy(b, w.reply), nil
}
func (w *statusWire) Write(_ context.Context, b []byte) (int, error) { return len(b), nil }
func TestUSBPrimeExceptionAndShortControl(t *testing.T) {
	for _, prime := range []bool{true, false} {
		wire := &statusWire{reply: "failed:"}
		_, err := usbCommand(context.Background(), wire, "echo priming", false, false, prime)
		if (err == nil) != prime {
			t.Fatal("priming exception escaped its scope", err)
		}
	}
	wire := &statusWire{reply: "success", short: true}
	if _, err := usbCommand(context.Background(), wire, "echo priming", false, false, true); err == nil || wire.reads != 0 {
		t.Fatal("short control accepted/continued", err)
	}
}
func TestUSBProtocolStopsOnEveryFailedTransfer(t *testing.T) {
	for _, name := range []string{"identify", "bulk", "read", "write-big"} {
		rows := referenceRows(t, name)
		for cut := 1; cut <= len(rows); cut++ {
			t.Run(fmt.Sprintf("%s-%d", name, cut), func(t *testing.T) {
				w := &referenceWire{records: rows, cut: cut}
				_, err := protocolCall(context.Background(), w, referenceArgs(t, name), false)
				if err == nil || w.index != cut {
					t.Fatalf("failure retried/ignored: %v, transfers=%d want%d", err, w.index, cut)
				}
			})
		}
	}
}

func TestUSBBulkContinuePollsWithoutReplay(t *testing.T) {
	w := &referenceWire{records: referenceRows(t, "bulk-continue")}
	if _, err := usbCommand(context.Background(), w, "echo priming", false, false, true); err != nil || w.index != len(w.records) || w.err != nil {
		t.Fatal(err, w.err, w.index)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	w = &referenceWire{records: referenceRows(t, "bulk-continue")}
	if _, err := usbCommand(ctx, w, "echo priming", false, false, true); !errors.Is(err, context.DeadlineExceeded) || w.index != 2 {
		t.Fatal("continued/replayed command after cancellation", err, w.index)
	}
}
