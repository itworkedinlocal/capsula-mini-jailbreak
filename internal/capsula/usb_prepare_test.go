package capsula

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type preparingTransport struct {
	Transport
	events     *[]string
	prepareErr error
}

func (t *preparingTransport) Prepare(notify func(string)) error {
	*t.events = append(*t.events, "prepare")
	if t.prepareErr != nil {
		return t.prepareErr
	}
	notify("helper-prepared")
	return nil
}
func (t *preparingTransport) Wait(time.Duration) error {
	*t.events = append(*t.events, "wait")
	return errors.New("test-stop-before-device")
}
func (t *preparingTransport) Close() {
	*t.events = append(*t.events, "close")
	t.Transport.Close()
}
func TestUSBPreparationPrecedesConnectionInstructions(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "cancelled-UAC"}[failure], func(t *testing.T) {
			b, m := modelBackend(t, "simple")
			var events []string
			prepared := &preparingTransport{Transport: m, events: &events}
			if failure {
				prepared.prepareErr = context.Canceled
			}
			b.Notify = func(message string) {
				if strings.Contains(message, "подключите только USB") {
					events = append(events, "connect-instructions")
				} else {
					events = append(events, message)
				}
			}
			b.NewTransport = func(_ context.Context, _ Resources, folder string) (Transport, error) {
				m.folder = folder
				return prepared, nil
			}
			_, err := b.Execute("diagnose", false)
			if err == nil {
				t.Fatal("fixture did not stop")
			}
			want := "prepare,helper-prepared,connect-instructions,wait,close"
			if failure {
				want = "prepare,close"
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			if strings.Join(events, ",") != want {
				t.Fatal(events, want)
			}
		})
	}
}
