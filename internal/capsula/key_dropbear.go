package capsula

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Dropbear 2026.94 src/ed25519.c: SSH string(type), SSH string(seed || public).
// Only the encoding is implemented here; all key operations use crypto/ed25519.
func newDropbearKey() ([]byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	var out bytes.Buffer
	for _, field := range [][]byte{[]byte("ssh-ed25519"), key} {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(field)))
		out.Write(field)
	}
	return out.Bytes(), nil
}

func dropbearPublic(key []byte) (string, error) {
	if len(key) != 83 || binary.BigEndian.Uint32(key) != 11 || string(key[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(key[15:19]) != 64 {
		return "", fmt.Errorf("неверный Dropbear Ed25519 host key")
	}
	derived := ed25519.NewKeyFromSeed(key[19:51])
	defer clear(derived)
	if !bytes.Equal(derived[32:], key[51:]) {
		return "", fmt.Errorf("public/private части host key не совпадают")
	}
	public, err := ssh.NewPublicKey(ed25519.PublicKey(key[51:]))
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public))), nil
}
