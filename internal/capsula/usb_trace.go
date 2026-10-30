package capsula

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"
)

// Capture metadata in memory; disk I/O happens only after a complete command.
// Payload bytes (including credentials inside RAM images) are never logged.
type usbTransferRecord struct {
	Operation   string `json:"operation"`
	Type        byte   `json:"type,omitempty"`
	Request     byte   `json:"request,omitempty"`
	Value       uint16 `json:"value,omitempty"`
	Index       uint16 `json:"index,omitempty"`
	Requested   int    `json:"requested"`
	Transferred int    `json:"transferred"`
	Started     string `json:"started_at"`
	Nanoseconds int64  `json:"duration_ns"`
	Error       string `json:"error,omitempty"`
}
type tracedUSBWire struct {
	usbWire
	rows []usbTransferRecord
}

func (w *tracedUSBWire) finish(row usbTransferRecord, start time.Time, n int, err error) (int, error) {
	row.Transferred = n
	row.Started = start.UTC().Format(time.RFC3339Nano)
	row.Nanoseconds = time.Since(start).Nanoseconds()
	if err != nil {
		row.Error = err.Error()
	}
	w.rows = append(w.rows, row)
	return n, err
}
func (w *tracedUSBWire) Control(ctx context.Context, typ, req byte, value, index uint16, b []byte) (int, error) {
	start := time.Now()
	n, err := w.usbWire.Control(ctx, typ, req, value, index, b)
	return w.finish(usbTransferRecord{Operation: "control", Type: typ, Request: req, Value: value, Index: index, Requested: len(b)}, start, n, err)
}
func (w *tracedUSBWire) Read(ctx context.Context, b []byte) (int, error) {
	start := time.Now()
	n, err := w.usbWire.Read(ctx, b)
	return w.finish(usbTransferRecord{Operation: "bulk-read", Requested: len(b)}, start, n, err)
}
func (w *tracedUSBWire) Write(ctx context.Context, b []byte) (int, error) {
	start := time.Now()
	n, err := w.usbWire.Write(ctx, b)
	return w.finish(usbTransferRecord{Operation: "bulk-write", Requested: len(b)}, start, n, err)
}
func (w *tracedUSBWire) save(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(f)
	encoder := json.NewEncoder(writer)
	for _, row := range w.rows {
		if err = encoder.Encode(row); err != nil {
			break
		}
	}
	if err == nil {
		err = writer.Flush()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	return ce
}
