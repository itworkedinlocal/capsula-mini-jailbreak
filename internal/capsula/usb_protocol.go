package capsula

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// The wire protocol is independent of host APIs and tested against the pinned
// Linux update helper. Only its existing allowlisted operations reach this code.
type usbWire interface {
	Control(context.Context, byte, byte, uint16, uint16, []byte) (int, error)
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
}

func usbControl(ctx context.Context, w usbWire, typ, req byte, value, index uint16, b []byte) error {
	n, err := w.Control(ctx, typ, req, value, index, b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("укороченный USB control: %d/%d", n, len(b))
	}
	return nil
}
func usbReply(ctx context.Context, w usbWire, size int) ([]byte, error) {
	b := make([]byte, size)
	n, err := w.Read(ctx, b)
	if n < 0 || n > size {
		return nil, fmt.Errorf("неверная длина USB ответа")
	}
	if err != nil {
		return b[:n], err
	}
	if n <= 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return bytes.TrimRight(b[:n], "\x00"), nil
}
func usbCommand(ctx context.Context, w usbWire, command string, tpl, launch, prime bool) ([]byte, error) {
	if len(command) > 63 {
		return nil, fmt.Errorf("слишком длинная USB команда")
	}
	data := make([]byte, 64)
	copy(data, command)
	req, index := byte(0x34), uint16(2)
	if tpl {
		req, index = 0x30, 1
	}
	if err := usbControl(ctx, w, 0x40, req, 0, index, data); err != nil {
		return nil, err
	}
	if tpl {
		reply := make([]byte, 64)
		if err := usbControl(ctx, w, 0xc0, 0x31, 0, 0, reply); err != nil {
			return reply, err
		}
		if !bytes.HasPrefix(reply, []byte("success")) {
			return reply, fmt.Errorf("USB download отказал: %q", bytes.TrimRight(reply, "\x00"))
		}
		return reply, nil
	}
	replyCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if launch {
		var launchCancel context.CancelFunc
		replyCtx, launchCancel = context.WithTimeout(replyCtx, 3*time.Second)
		defer launchCancel()
	}
	for {
		reply, err := usbReply(replyCtx, w, 512)
		if launch {
			if ctx.Err() != nil {
				return reply, ctx.Err()
			}
			return reply, nil // RAM console/readback validates the actual transition.
		}
		if err != nil {
			return reply, err
		}
		if bytes.HasPrefix(reply, []byte("success")) || (prime && string(reply) == "failed:") {
			return reply, nil
		}
		if bytes.HasPrefix(reply, []byte("Continue:34")) {
			// Poll status only: replaying the original command would change semantics.
			if err = waitContext(replyCtx, 3*time.Second); err != nil {
				return reply, err
			}
			continue
		}
		return reply, fmt.Errorf("USB команда отказала: %q", reply)
	}
}

func mediaChecksum(b []byte) uint32 {
	var sum uint32
	for len(b) >= 4 {
		sum += binary.LittleEndian.Uint32(b)
		b = b[4:]
	}
	var tail [4]byte
	copy(tail[:], b)
	return sum + binary.LittleEndian.Uint32(tail[:])
}

func protocolCall(ctx context.Context, w usbWire, a []string, launch bool) ([]byte, error) {
	switch a[0] {
	case "identify":
		data := make([]byte, 7)
		if err := usbControl(ctx, w, 0xc0, 0x20, 0, 0, data); err != nil {
			return nil, err
		}
		fields := make([]string, 7)
		for i, n := range data {
			fields[i] = strconv.Itoa(int(n))
		}
		return []byte("firmware version " + strings.Join(fields, "-")), nil
	case "bulkcmd":
		return usbCommand(ctx, w, a[1], false, launch, a[1] == "echo priming")
	case "mread":
		size, err := strconv.ParseInt(a[4], 0, 64)
		if err != nil || size <= 0 {
			return nil, fmt.Errorf("неверный USB read size")
		}
		if _, err = usbCommand(ctx, w, "upload "+a[1]+" "+a[2]+" normal "+a[4], false, false, false); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(a[5], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		for left := size; left > 0; {
			n := int(min(left, 65536))
			meta := make([]byte, 16)
			if err = usbControl(ctx, w, 0xc0, 0x33, 4096, uint16((n+4095)/4096), meta); err != nil {
				return nil, err
			}
			b := make([]byte, n)
			for off := 0; off < n; {
				got, e := w.Read(ctx, b[off:])
				if e != nil {
					return nil, e
				}
				if got <= 0 || got > n-off {
					return nil, io.ErrUnexpectedEOF
				}
				off += got
			}
			if _, err = f.Write(b); err != nil {
				return nil, err
			}
			left -= int64(n)
		}
		return nil, f.Sync()
	case "mwrite":
		data, err := os.ReadFile(a[1])
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > 0x800000 {
			return nil, fmt.Errorf("неверный RAM chunk")
		}
		cmd := fmt.Sprintf("download mem %s normal %#x", a[3], len(data))
		if _, err = usbCommand(ctx, w, cmd, true, false, false); err != nil {
			return nil, err
		}
		for off := 0; off < len(data); {
			block := data[off:min(off+65536, len(data))]
			header := make([]byte, 32)
			binary.LittleEndian.PutUint32(header[4:], uint32(len(block)))
			binary.LittleEndian.PutUint32(header[8:], uint32(off/4096))
			binary.LittleEndian.PutUint32(header[12:], mediaChecksum(block))
			binary.LittleEndian.PutUint16(header[16:], 0xef)
			binary.LittleEndian.PutUint16(header[18:], 256)
			if err = usbControl(ctx, w, 0x40, 0x32, 1, 0xffff, header); err != nil {
				return nil, err
			}
			n, e := w.Write(ctx, block)
			if e != nil {
				return nil, e
			}
			if n != len(block) {
				return nil, io.ErrShortWrite
			}
			deadline := time.Now().Add(90 * time.Second)
			for {
				ack, e := usbReply(ctx, w, 512)
				if e != nil {
					return nil, e
				}
				if bytes.HasPrefix(ack, []byte("OK!!")) {
					break
				}
				if !bytes.HasPrefix(ack, []byte("Continue:32")) {
					return nil, fmt.Errorf("неверный RAM write ACK: %q", ack)
				}
				if time.Now().After(deadline) {
					return nil, context.DeadlineExceeded
				}
				if err = waitContext(ctx, 500*time.Millisecond); err != nil {
					return nil, err
				}
			}
			off += len(block)
		}
		return usbCommand(ctx, w, "download get_status", false, false, false)
	}
	return nil, fmt.Errorf("неподдерживаемая USB операция")
}
