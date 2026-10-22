package consoleserver

import (
	"flag"
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestHistoryCapacityEnvironmentDefaultsAndCLIOverride(t *testing.T) {
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	maximum, minimumFree, err := historyCapacityDefaults(lookup(nil))
	if err != nil || maximum != console.DefaultHistoryArchiveMaxBytes || minimumFree != console.DefaultHistoryMinFreeBytes {
		t.Fatalf("default capacity = %d/%d err=%v", maximum, minimumFree, err)
	}
	maximum, minimumFree, err = historyCapacityDefaults(lookup(map[string]string{
		historyMaxBytesEnv: "3221225472", historyMinFreeEnv: "805306368",
	}))
	if err != nil || maximum != 3221225472 || minimumFree != 805306368 {
		t.Fatalf("environment capacity = %d/%d err=%v", maximum, minimumFree, err)
	}
	flags := flag.NewFlagSet("capacity", flag.ContinueOnError)
	flags.Int64Var(&maximum, "history-max-bytes", maximum, "")
	flags.Int64Var(&minimumFree, "history-min-free-bytes", minimumFree, "")
	if err := flags.Parse([]string{"-history-max-bytes=4294967296", "-history-min-free-bytes=1073741824"}); err != nil {
		t.Fatal(err)
	}
	if maximum != 4294967296 || minimumFree != 1073741824 {
		t.Fatalf("explicit CLI did not override environment defaults: %d/%d", maximum, minimumFree)
	}
}

func TestHistoryCapacityEnvironmentRejectsNonCanonicalOrUnsafeValues(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "+1", " 1", "1 ", "01", "1e9", "9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			_, _, err := historyCapacityDefaults(func(name string) (string, bool) {
				if name == historyMaxBytesEnv {
					return value, true
				}
				return "536870912", true
			})
			if err == nil {
				t.Fatalf("invalid environment value %q was accepted", value)
			}
		})
	}
}
