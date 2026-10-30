package capsula

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSSHServer(t *testing.T) (string, int, string) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() != "root" || string(pw) != "fixture пароль" {
			return nil, fmt.Errorf("bad password")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var connections []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			c.Close()
		}
	})
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			go func() {
				_, channels, requests, e := ssh.NewServerConn(c, config)
				if e != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						channel.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, reqs, e := channel.Accept()
					if e != nil {
						return
					}
					go func() {
						defer ch.Close()
						for req := range reqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var command struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &command)
							req.Reply(true, nil)
							code := uint32(0)
							switch command.Command {
							case "/usr/lib/capsula-root/supervisor identity":
								fmt.Fprint(ch, "0\n0\n")
							case "true":
							default:
								fmt.Fprint(ch.Stderr(), "fixture command failure")
								code = 19
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
							return
						}
					}()
				}
			}()
		}
	}()
	return "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}
func TestSSHRootSuccessAndFullFailureAreDistinct(t *testing.T) {
	host, port, key := testSSHServer(t)
	report, e := VerifySSH(context.Background(), host, port, key, []byte("fixture пароль"), t.TempDir(), "basic", nil)
	if e != nil || !report.Root || report.Full {
		t.Fatal(report, e)
	}
	report, e = VerifySSH(context.Background(), host, port, key, []byte("fixture пароль"), t.TempDir(), "full", &Manifest{})
	if e == nil || !report.Root || report.Full || report.Stages["noninteractive"].Status != "failed" {
		t.Fatal(report, e)
	}
	if !strings.Contains(e.Error(), "fixture command failure") {
		t.Fatal("lost stderr", e)
	}
}
func TestSSHRejectsWrongPasswordHostKeyAndTimeout(t *testing.T) {
	host, port, key := testSSHServer(t)
	report, e := VerifySSH(context.Background(), host, port, key, []byte("wrong"), t.TempDir(), "basic", nil)
	if e == nil || report.Root {
		t.Fatal("wrong password accepted")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(priv)
	report, e = VerifySSH(context.Background(), host, port, string(ssh.MarshalAuthorizedKey(other.PublicKey())), []byte("fixture пароль"), t.TempDir(), "basic", nil)
	if e == nil || report.Root || !strings.Contains(e.Error(), "host key") {
		t.Fatal("wrong key accepted", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = VerifySSH(ctx, host, port, key, []byte("fixture пароль"), t.TempDir(), "basic", nil)
	if e == nil {
		t.Fatal("cancel ignored")
	}
}
