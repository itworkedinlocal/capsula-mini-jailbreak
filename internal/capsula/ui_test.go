package capsula

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestMenuNavigationAndInvalidChoice(t *testing.T) {
	for _, test := range []struct{ input, command, action string }{
		{"9\n5\n0\n2\n", "update", "status"},
		{"5\n3\n", "rollback", "status"},
		{"4\n2\n", "entware", "install"},
		{"4\n0\n0\n", "", ""},
	} {
		var output bytes.Buffer
		terminal := Terminal{Output: &output, Reader: bufio.NewReader(strings.NewReader(test.input))}
		command, action, err := terminal.Menu()
		if err != nil || command != test.command || action != test.action {
			t.Fatalf("%q => %s %s %v", test.input, command, action, err)
		}
		if strings.Contains(output.String(), "\x1b[") {
			t.Fatal("ANSI in non-TTY output")
		}
	}
}

func TestJSONOfflineOutputIsSingleDocument(t *testing.T) {
	sourceResources(t)
	t.Chdir("../..")
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var output, diagnostics bytes.Buffer
	code := Main([]string{"diagnose", "--offline", "--json"}, input, &output, &diagnostics)
	if code != 0 {
		t.Fatal(code, diagnostics.String())
	}
	if err = UniqueJSON(output.Bytes()); err != nil {
		t.Fatal("mixed JSON stdout", err)
	}
}

func TestProgressPipeAndVerbose(t *testing.T) {
	var output bytes.Buffer
	p := progressDisplay{writer: &output}
	for n := 1; n <= 100; n++ {
		p.notify("RAW/OOB: " + strconv.Itoa(n) + "%")
	}
	p.event(ProgressEvent{Stage: "debug", Detail: "internal", Verbose: true})
	if strings.Count(output.String(), "\n") != 2 || strings.Contains(output.String(), "internal") || strings.Contains(output.String(), "\r") {
		t.Fatal(output.String())
	}
	p.verbose = true
	p.event(ProgressEvent{Stage: "debug", Detail: "internal", Verbose: true})
	if !strings.Contains(output.String(), "internal") {
		t.Fatal("verbose omitted")
	}
}
