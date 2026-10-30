package capsula

import "os"

// Run supplies host startup/teardown only. Main remains usable by CLI tests.
func Run() int {
	finish, handled, code := platformEntry()
	if handled {
		return code
	}
	defer finish()
	return Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}
