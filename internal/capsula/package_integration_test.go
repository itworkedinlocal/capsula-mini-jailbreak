package capsula

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Exercise fresh credentials through the actual host helper and package builder
// on both platforms without a device.
func TestPackageBuilderFreshCredentials(t *testing.T) {
	stock := StockBundle{Files: map[string][]byte{
		"/etc/passwd":                 []byte("root:x:0:0:root:/root:/bin/sh\n"),
		"/etc/shadow":                 []byte("root:!:0:0:99999:7:::\n"),
		"/etc/profile":                []byte("id=`id -u`\n"),
		"/etc/init.d/S89usbgadget.sh": []byte("#!/bin/sh\n"),
	}, Kernels: []string{"4.9.113"}}
	r := sourceResources(t)
	device := filepath.Join(t.TempDir(), "Капсула с пробелами")
	first := filepath.Join(t.TempDir(), "install")
	id := testProfile(t).Identity
	if _, err := BuildPackage(r, first, device, id, stock, func() ([]byte, error) {
		return []byte("пароль 😀"), nil
	}, true); err != nil {
		t.Fatal(err)
	}
	hash, err := os.ReadFile(filepath.Join(device, "credentials", "root-password.hash"))
	if err != nil || !passwordHashRE.Match(bytes.TrimSuffix(hash, []byte("\n"))) || bytes.ContainsRune(hash, '\r') {
		t.Fatal("invalid saved password hash", err)
	}
	archive, err := os.Open(filepath.Join(first, "overlay-files.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if err != nil {
			t.Fatal("missing shadow in package", err)
		}
		if header.Name == "etc/shadow" {
			shadow, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			got, err := rootPasswordHash(shadow)
			if err != nil || !bytes.Equal(got, bytes.TrimSuffix(hash, []byte("\n"))) {
				t.Fatal("saved password hash differs from packaged shadow", err)
			}
			break
		}
	}
	next := filepath.Join(t.TempDir(), "update")
	if _, err := BuildPackage(r, next, device, id, stock, func() ([]byte, error) {
		t.Fatal("requested password despite saved credentials")
		return nil, nil
	}, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server-hostkey.pub", "overlay-files.tar"} {
		a, err := FileSHA(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := FileSHA(filepath.Join(next, name))
		if err != nil || a != b {
			t.Fatal("credentials changed on update", err)
		}
	}
}
