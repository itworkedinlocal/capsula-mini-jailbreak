package capsula

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A serial stream whose read stays pending until data or cancellation arrives.
// Scripted writes model getty discarding input before the shell is ready.
func scriptedConsole(onWrite func([]byte, chan<- []byte) error) (consoleStream, *atomic.Int32) {
	data := make(chan []byte, 128)
	active := new(atomic.Int32)
	var pending []byte
	return consoleStream{
		read: func(ctx context.Context, b []byte) (int, error) {
			active.Add(1)
			defer active.Add(-1)
			if len(pending) == 0 {
				select {
				case pending = <-data:
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			n := copy(b, pending)
			pending = pending[n:]
			return n, nil
		},
		write: func(ctx context.Context, b []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return onWrite(b, data)
		},
		status: func() error { return nil },
	}, active
}

func readyReply(t *testing.T, probe []byte, rc int) []byte {
	t.Helper()
	// The terminal echo contains the format and argument separately, never the
	// actual reply. An old prompt/echo must not release the working command.
	m := regexp.MustCompile(`CAPSULA_READY_%s:0\\n' ([0-9a-f]{64})\n$`).FindSubmatch(probe)
	if m == nil {
		t.Fatalf("not a read-only readiness challenge: %q", probe)
	}
	reply := fmt.Sprintf("\nCAPSULA_READY_%s:%d\r\n", m[1], rc)
	if bytes.Contains(probe, bytes.TrimSpace([]byte(reply))) {
		t.Fatal("terminal echo can masquerade as a ready response")
	}
	return []byte(reply)
}

func TestReadyConsoleWaitsForDelayedShellAndSendsOperationOnce(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	end, operation := "CAPSULA_END_"+nonce, "WORKING-COMMAND\n"
	probes, operations, ready := 0, 0, false
	stream, active := scriptedConsole(func(b []byte, data chan<- []byte) error {
		switch string(b) {
		case "\x03\n":
			data <- []byte("booting\r\n~ # \x1b[6n")
		case operation:
			if !ready {
				t.Fatal("operation sent before shell readiness")
			}
			operations++
			data <- []byte("\n" + end + ":0\r\n")
		default:
			probes++
			if !bytes.Contains(b, []byte(nonce)) {
				t.Fatal("readiness not tied to the requested RAM session")
			}
			data <- bytes.Clone(b) // echo is not proof of execution
			if probes == 4 {
				ready = true
				reply := readyReply(t, b, 0)
				data <- reply[:len(reply)-4] // split marker as on the serial link
				data <- reply[len(reply)-4:]
			}
		}
		return nil
	})
	var output bytes.Buffer
	err := exchangeReadyConsole(context.Background(), stream, operation, end, &output, time.Second, time.Second, 5*time.Millisecond)
	if err != nil || probes != 4 || operations != 1 || active.Load() != 0 {
		t.Fatal(err, probes, operations, active.Load(), output.String())
	}
}

func TestReadyConsoleRejectsBootEchoAndForeignOrFailedReply(t *testing.T) {
	for _, response := range []string{"echo-only", "foreign-session", "failed-reply"} {
		t.Run(response, func(t *testing.T) {
			operations := 0
			stream, active := scriptedConsole(func(b []byte, data chan<- []byte) error {
				if string(b) == "\x03\n" {
					return nil
				}
				if string(b) == "WORKING-COMMAND\n" {
					operations++
					return nil
				}
				data <- append([]byte("boot ready\n~ # "), b...)
				switch response {
				case "foreign-session":
					data <- []byte("\nCAPSULA_READY_" + strings.Repeat("f", 64) + ":0\n")
				case "failed-reply":
					data <- readyReply(t, b, 1)
				}
				return nil
			})
			var output bytes.Buffer
			err := exchangeReadyConsole(context.Background(), stream, "WORKING-COMMAND\n", "CAPSULA_END_"+strings.Repeat("a", 64), &output, time.Second, 35*time.Millisecond, 5*time.Millisecond)
			if err == nil || !strings.Contains(err.Error(), "рабочая команда не отправлялась") || operations != 0 || active.Load() != 0 {
				t.Fatal(err, operations, active.Load())
			}
			if response != "failed-reply" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("startup deadline lost:", err)
			}
		})
	}
}

func TestReadyConsoleCancellationAndStartupFailureJoinReceiver(t *testing.T) {
	for _, failure := range []string{"cancel", "write", "receive"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			problem := errors.New("serial failure")
			operations := 0
			stream, active := scriptedConsole(func(b []byte, data chan<- []byte) error {
				if string(b) == "WORKING-COMMAND\n" {
					operations++
				}
				if string(b) != "\x03\n" {
					if failure == "cancel" {
						cancel()
					} else if failure == "write" {
						return problem
					} else {
						data <- readyReply(t, b, 0)
					}
				}
				return nil
			})
			if failure == "receive" {
				stream.status = func() error { return problem }
			}
			var output bytes.Buffer
			err := exchangeReadyConsole(ctx, stream, "WORKING-COMMAND\n", "CAPSULA_END_"+strings.Repeat("a", 64), &output, time.Second, time.Second, 5*time.Millisecond)
			want := problem
			if failure == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || operations != 0 || active.Load() != 0 {
				t.Fatal(err, operations, active.Load())
			}
		})
	}
}

func TestReadyConsoleNeverReplaysUncertainOperation(t *testing.T) {
	for _, failure := range []string{"write", "timeout", "receive"} {
		t.Run(failure, func(t *testing.T) {
			operations := 0
			problem := errors.New("operation response lost")
			stream, active := scriptedConsole(func(b []byte, data chan<- []byte) error {
				if string(b) == "\x03\n" {
					return nil
				}
				if string(b) == "WORKING-COMMAND\n" {
					operations++
					if failure == "write" {
						return problem // may already have reached the device
					}
					if failure == "receive" {
						data <- []byte("partial response\n")
					}
					return nil
				}
				data <- readyReply(t, b, 0)
				return nil
			})
			if failure == "receive" {
				read := stream.read
				stream.read = func(ctx context.Context, b []byte) (int, error) {
					n, err := read(ctx, b)
					if bytes.Contains(b[:n], []byte("partial response")) {
						return n, problem
					}
					return n, err
				}
			}
			var output bytes.Buffer
			err := exchangeReadyConsole(context.Background(), stream, "WORKING-COMMAND\n", "CAPSULA_END_"+strings.Repeat("a", 64), &output, 25*time.Millisecond, time.Second, 5*time.Millisecond)
			want := problem
			if failure == "timeout" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || operations != 1 || active.Load() != 0 {
				t.Fatal(err, operations, active.Load())
			}
		})
	}
}

func TestConsoleResponseBurstAndSplitMarker(t *testing.T) {
	end := "CAPSULA_END_" + strings.Repeat("a", 64)
	body := []byte(strings.Repeat("0123456789abcdef\r\n", 100000) + "\n" + end + ":0\r\n")
	for _, split := range []bool{false, true} {
		var output bytes.Buffer
		offset, checks := 0, 0
		err := collectConsoleResponse(context.Background(), &output, end, func(_ context.Context, b []byte) (int, error) {
			limit := len(b)
			if split {
				marker := len(body) - len(end) - 5
				if offset >= marker {
					limit = 1
				} else if offset+limit > marker {
					limit = marker - offset
				}
			}
			n := copy(b[:limit], body[offset:])
			offset += n
			if n == 0 {
				return 0, errors.New("end marker lost")
			}
			return n, nil
		}, func() error { checks++; return nil })
		if err != nil || !bytes.Equal(output.Bytes(), body) || checks == 0 {
			t.Fatal(split, err, output.Len(), len(body), checks)
		}
	}
}

func TestConsoleResponseRejectsReceiveLossEvenWithCompleteFrame(t *testing.T) {
	end := "CAPSULA_END_test"
	loss := errors.New("COM receive overflow")
	var output bytes.Buffer
	err := collectConsoleResponse(context.Background(), &output, end, func(_ context.Context, b []byte) (int, error) {
		return copy(b, []byte("\n"+end+":0\r\n")), nil
	}, func() error { return loss })
	if !errors.Is(err, loss) || output.Len() == 0 {
		t.Fatal(err, output.Len())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = collectConsoleResponse(ctx, &output, end, func(context.Context, []byte) (int, error) { t.Fatal("read after cancellation"); return 0, nil }, func() error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
