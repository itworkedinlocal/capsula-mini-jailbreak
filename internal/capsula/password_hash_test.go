package capsula

import (
	"strings"
	"testing"
)

func TestGeneratedPasswordHashLineEndings(t *testing.T) {
	hash := "$6$rounds=100000$0123456789abcdef$" + strings.Repeat("A", 86)
	for _, tc := range []struct{ name, ending string }{
		{"no-newline", ""}, {"linux-LF", "\n"}, {"windows-CRLF", "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeGeneratedPasswordHash([]byte(hash + tc.ending))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != hash+"\n" {
				t.Fatal("generated hash was not saved with a single LF")
			}
		})
	}
}

func TestGeneratedPasswordHashRejectsMalformedOutput(t *testing.T) {
	hash := "$6$rounds=100000$0123456789abcdef$" + strings.Repeat("A", 86)
	for _, output := range []string{
		"", hash + "\r", " " + hash, hash + " ", hash + "\n\n", hash + "\r\n\r\n",
		hash + "\n" + hash, "diagnostic\n" + hash, hash + "\x00", hash[:len(hash)-1], hash + "A",
		strings.Replace(hash, "rounds=100000", "rounds=1000", 1),
		strings.Replace(hash, "0123456789abcdef", "0123456789abcdeg", 1),
	} {
		if _, err := normalizeGeneratedPasswordHash([]byte(output)); err == nil {
			t.Fatal("malformed password helper output accepted")
		}
	}
}
