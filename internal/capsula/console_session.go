package capsula

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type consoleStream struct {
	read   func(context.Context, []byte) (int, error)
	write  func(context.Context, []byte) error
	status func() error
	ready  func()
}

// exchangeReadyConsole repeats only a read-only shell challenge. The operation
// is sent once, after a fresh response proves that this RAM session can execute
// commands. A boot banner, prompt, echoed input or an old session cannot do so.
func exchangeReadyConsole(ctx context.Context, stream consoleStream, line, end string, output *bytes.Buffer, commandTimeout, startupTimeout, retryInterval time.Duration) error {
	nonce := strings.TrimPrefix(end, "CAPSULA_END_")
	if !digestRE.MatchString(nonce) || end != "CAPSULA_END_"+nonce {
		return fmt.Errorf("неверный идентификатор RAM-сеанса")
	}
	ready := "CAPSULA_READY_" + RandomHex(32)
	// Keep the response marker out of the command text: terminal echo must not
	// satisfy readiness. This command only reads a file in the initramfs.
	probe := fmt.Sprintf("test \"$(/bin/busybox cat /capsula-run-id)\" = %s && printf '\\nCAPSULA_READY_%%s:0\\n' %s\n", nonce, strings.TrimPrefix(ready, "CAPSULA_READY_"))
	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	result := make(chan error, 1)
	go func() { result <- collectConsoleResponse(startupCtx, output, ready, stream.read, stream.status) }()
	startup := func() error {
		if err := stream.write(startupCtx, []byte("\x03\n")); err != nil {
			return err
		}
		if err := stream.write(startupCtx, []byte(probe)); err != nil {
			return err
		}
		ticker := time.NewTicker(retryInterval)
		defer ticker.Stop()
		for {
			select {
			case err := <-result:
				// The receive loop has finished; all accesses to output are joined.
				result = nil
				return err
			case <-startupCtx.Done():
				return startupCtx.Err()
			case <-ticker.C:
				// Do not send another Ctrl+C: a late shell may be running a probe.
				if err := stream.write(startupCtx, []byte(probe)); err != nil {
					return err
				}
			}
		}
	}()
	cancelStartup()
	if result != nil {
		<-result // cancel/join pending I/O before returning or issuing a command
	}
	if startup != nil {
		return fmt.Errorf("RAM-консоль не подтвердила готовность; рабочая команда не отправлялась: %w", startup)
	}
	if !bytes.Contains(output.Bytes(), []byte("\n"+ready+":0\n")) && !bytes.Contains(output.Bytes(), []byte("\n"+ready+":0\r\n")) {
		return fmt.Errorf("RAM-консоль не подтвердила готовность; рабочая команда не отправлялась: неверный ответ")
	}
	if stream.ready != nil {
		stream.ready()
	}

	commandCtx, cancelCommand := context.WithTimeout(ctx, commandTimeout)
	defer cancelCommand()
	response := make(chan error, 1)
	go func() { response <- collectConsoleResponse(commandCtx, output, end, stream.read, stream.status) }()
	// Start draining RX before the operation can produce its first output burst.
	if err := stream.write(commandCtx, []byte(line)); err != nil {
		cancelCommand()
		<-response
		return err // delivery is uncertain: never replay the operation
	}
	return <-response
}

func collectConsoleResponse(ctx context.Context, output *bytes.Buffer, end string, read func(context.Context, []byte) (int, error), status func() error) error {
	ending := regexp.MustCompile("\n" + regexp.QuoteMeta(end) + `:[0-9]+\r?\n`)
	buf := make([]byte, 16384)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := read(ctx, buf)
		if n < 0 || n > len(buf) {
			return fmt.Errorf("неверная длина ответа RAM-консоли")
		}
		if err != nil {
			return err
		}
		if output.Len()+n > 8<<20 {
			return fmt.Errorf("слишком большой ответ RAM")
		}
		previous := output.Len()
		output.Write(buf[:n])
		if err := status(); err != nil {
			return err
		}
		// Scan only new bytes plus a split-marker overlap to keep draining bursts.
		if ending.Match(output.Bytes()[max(0, previous-len(end)-32):]) {
			return nil
		}
	}
}
